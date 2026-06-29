import os
import fitz  # PyMuPDF
import numpy as np
from pathlib import Path
from sentence_transformers import SentenceTransformer
from sklearn.preprocessing import normalize

class libtiffRAG:
    def __init__(self, doc_folder="documents", model_name="intfloat/e5-base-v2"):
        self.embedder = SentenceTransformer(model_name)
        self.doc_folder = doc_folder
        self.docs = []
        self.metadata = []
        self.embeddings = None
        self.model_loaded = False

    def extract_text_from_pdf(self, pdf_path):
        doc = fitz.open(pdf_path)
        extracted_text = []
        for page in doc:
            text = page.get_text("text")
            if text.strip():
                extracted_text.append(text.strip())
        return "\n".join(extracted_text)

    def chunk_text(self, text, chunk_size=500):
        words = text.split()
        return [" ".join(words[i:i + chunk_size]) for i in range(0, len(words), chunk_size)]

    def load_documents(self):
        self.docs = []
        self.metadata = []
        if not os.path.isdir(self.doc_folder):
            print(f"[WARN] Document folder does not exist: {self.doc_folder}")
            return
        for fname in os.listdir(self.doc_folder):
            path = os.path.join(self.doc_folder, fname)
            if fname.endswith(".txt"):
                with open(path, "r", encoding="utf-8") as f:
                    for line in f:
                        ln = line.strip()
                        if len(ln) > 10:
                            self.docs.append(ln)
                            self.metadata.append({"source": fname})
            elif fname.endswith(".pdf"):
                text = self.extract_text_from_pdf(path)
                if not text.strip():
                    print(f"[SKIP] No content extracted from {fname}")
                    continue
                chunks = self.chunk_text(text)
                for i, para in enumerate(chunks):
                    if len(para.strip()) > 10:
                        self.docs.append(para.strip())
                        self.metadata.append({"source": fname, "chunk_index": i})

    def build_index(self):
        if not self.docs:
            print("[ERROR] No documents loaded. Cannot build index.")
            return
        self.embeddings = self.embedder.encode(self.docs, convert_to_numpy=True)
        self.embeddings = normalize(self.embeddings)
        self.model_loaded = True

    def get_top_chunks(self, query, top_k=3):
        if not self.model_loaded or self.embeddings is None:
            print("[WARN] Index not built. Building now...")
            self.load_documents()
            self.build_index()

        if not isinstance(query, str) or not query.strip():
            raise ValueError("Query must be a non-empty string.")

        query_embedding = self.embedder.encode([query], convert_to_numpy=True)
        query_embedding = normalize(query_embedding)

        scores = np.dot(query_embedding, self.embeddings.T)
        top_indices = np.argsort(-scores, axis=1)[:, :top_k]

        return [self.docs[i] for i in top_indices[0]]

    def get_rag_context_for_fields(self, field_list, prefix="libtiff", top_k=3):
        """
        Return concatenated top chunks for a list of field/term queries.
        Default prefix is 'libtiff' to bias results toward libtiff-specific docs.
        """
        if not field_list:
            return ""
        all_chunks = []
        for field in field_list:
            query = f"{prefix} {field}".strip()
            try:
                top_chunks = self.get_top_chunks(query, top_k=top_k)
            except Exception as e:
                print(f"[WARN] get_top_chunks failed for query '{query}': {e}")
                top_chunks = []
            all_chunks.extend(top_chunks)
        deduped_chunks = list(dict.fromkeys(all_chunks))  # remove duplicates, preserve order
        return "\n".join(deduped_chunks)
