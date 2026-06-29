import re
from pycparser import c_parser
from RAG_module import libtiffRAG  # RAG module integration


def strip_preprocessor_directives(code):
    """
    Remove only the first opening ```c (or ```) and the last ``` fence at the end,
    keeping everything else, including #include lines, typedefs, comments, etc.
    """
    if not isinstance(code, str):
        return ""

    # Remove first opening fence, only the ```c or ``` at the very start
    # Use more precise pattern to avoid matching #include lines
    code = re.sub(r'^\s*```(?:c|C)?\s*\n', '', code, count=1, flags=re.MULTILINE)

    # Remove last closing fence, only if it is at the very end
    code = re.sub(r'\n\s*```\s*$', '', code, count=1, flags=re.MULTILINE)

    return code
def extract_mutatable_fields_from_ast(c_code):
    
    parser = c_parser.CParser()
    clean_code = strip_preprocessor_directives(c_code)

    # Initialize mutatables for libtiff
    mutatables = {
        "struct_fields": [],
        "string_constants": [],
        "buffer_fields": [],
        "tiff_call_buffers": [],
        "pointer_operations": [],
        "file_operations": [],
        "tiff_tags": [],
        "tiff_functions": [],
        "compression_fields": []
    }

    try:
        ast = parser.parse(clean_code, filename='<none>')
    except Exception as e:
        print(f"AST parsing failed: {e}")
        return mutatables

    # Store original code lines for precise extraction
    code_lines = c_code.split('\n')

    def get_code_from_coord(coord):
        """Extract actual code using coordinate information"""
        if coord is None:
            return ""
        try:
            line_num = coord.line - 1  # Convert to 0-based index
            if 0 <= line_num < len(code_lines):
                return code_lines[line_num].strip()
        except:
            pass
        return ""

    def get_node_actual_code(node):
        """Get the actual source code for a node"""
        if hasattr(node, 'coord') and node.coord:
            return get_code_from_coord(node.coord)
        
        # Fallback: try to reconstruct from node properties
        if hasattr(node, 'name'):
            return str(node.name)
        if hasattr(node, 'value'):
            return str(node.value)
        return str(node)

    class Visitor:
        def __init__(self):
            self.current_function = None
            
        def visit(self, node):
            if node is None:
                return
            method = 'visit_' + node.__class__.__name__
            visitor = getattr(self, method, self.generic_visit)
            visitor(node)
            
        def generic_visit(self, node):
            for _, child in node.children():
                self.visit(child)
                
        def visit_FuncDef(self, node):
            # Track which function we're in
            if hasattr(node.decl, 'name'):
                self.current_function = get_node_actual_code(node.decl)
            self.generic_visit(node)
            self.current_function = None
            
        def visit_Decl(self, node):
            """Capture variable declarations with actual code"""
            if hasattr(node, 'type') and hasattr(node, 'name'):
                decl_code = get_node_actual_code(node)
                
                # Capture string constants from declarations
                if 'char' in decl_code and '=' in decl_code:
                    var_name = get_node_actual_code(node.name)
                    if '"' in decl_code:
                        # Extract the actual string value from source
                        match = re.search(r'=\s*"([^"]*)"', decl_code)
                        if match:
                            mutatables['string_constants'].append(
                                (var_name, match.group(1), self.current_function, decl_code)
                            )
                
                # Capture buffer/array declarations (for TIFF data)
                if '[' in decl_code and ']' in decl_code:
                    buffer_types = ['uint8_t', 'uint16_t', 'uint32_t', 'unsigned char', 
                                   'TIFFRGBValue', 'tdata_t', 'tstrip_t']
                    if any(buf_type in decl_code for buf_type in buffer_types):
                        mutatables['buffer_fields'].append(
                            (get_node_actual_code(node.name), "array_decl", decl_code, self.current_function)
                        )
                
                # Check for TIFF-related tags in declarations
                tiff_tag_keywords = ['TIFFTAG_', 'ImageWidth', 'ImageLength', 'BitsPerSample', 
                                    'Compression', 'SamplesPerPixel', 'Photometric',
                                    'RowsPerStrip', 'StripOffsets', 'StripByteCounts']
                if any(keyword in decl_code for keyword in tiff_tag_keywords):
                    # This is a TIFF tag declaration
                    tag_name = get_node_actual_code(node.name)
                    # Try to extract the value
                    value_match = re.search(r'=\s*([^;]+)', decl_code)
                    value = value_match.group(1).strip() if value_match else "unknown"
                    mutatables['tiff_tags'].append((tag_name, value, "tifftag", decl_code))
            
            self.generic_visit(node)
            
        def visit_Assignment(self, node):
            """Capture assignments with actual source code"""
            assignment_code = get_node_actual_code(node)
            lname = getattr(node.lvalue, '__class__', None).__name__ if node.lvalue else None
            
            if lname == 'StructRef':
                field = getattr(getattr(node.lvalue, 'field', None), 'name', 
                               get_node_actual_code(node.lvalue.field))
                value_code = get_node_actual_code(node.rvalue)
                mutatables['struct_fields'].append(
                    (field, value_code, self.current_function, assignment_code)
                )
                
            elif lname == 'ArrayRef':
                target = get_node_actual_code(getattr(node.lvalue, 'name', None))
                index = get_node_actual_code(getattr(node.lvalue, 'subscript', None))
                value_code = get_node_actual_code(node.rvalue)
                
                # Buffer detection for libtiff
                buffer_indicators = ["buffer", "buf", "data", "scanline", "strip", "tile",
                                   "raster", "image", "pixel", "sample", "plane"]
                if target and any(k in target.lower() for k in buffer_indicators):
                    mutatables['buffer_fields'].append(
                        (target, index or "unknown", value_code, self.current_function, assignment_code)
                    )

        def visit_FuncCall(self, node):
            """Capture function calls with actual arguments"""
            call_code = get_node_actual_code(node)
            fname = getattr(getattr(node, 'name', None), 'name', 
                           get_node_actual_code(node.name) if node.name else "")
            
            # libtiff function detection
            tiff_funcs = ['TIFFOpen', 'TIFFReadScanline', 'TIFFWriteScanline',
                         'TIFFReadEncodedStrip', 'TIFFWriteEncodedStrip',
                         'TIFFReadRawStrip', 'TIFFWriteRawStrip',
                         'TIFFReadEncodedTile', 'TIFFWriteEncodedTile',
                         'TIFFReadRGBATile', 'TIFFReadRGBAStrip',
                         'TIFFGetField', 'TIFFSetField', 'TIFFClose',
                         'TIFFSetDirectory', 'TIFFCurrentDirectory']
            
            is_tiff_call = (fname and (fname.startswith("TIFF") or 
                         any(func in fname for func in tiff_funcs) or
                         "tiff" in fname.lower()))
            
            if is_tiff_call:
                # Add to tiff_functions
                mutatables['tiff_functions'].append((fname, self.current_function, call_code))
                
                args = []
                if getattr(node, 'args', None) and getattr(node.args, 'exprs', None):
                    args = [get_node_actual_code(a) for a in node.args.exprs]
                    
                for i, a in enumerate(args):
                    # Arguments that are likely to be buffers/strings/files
                    arg_indicators = ["data", "buf", "buffer", "raster", "scanline",
                                    "strip", "tile", "filename", "mode", "name",
                                    "image", "pixel", "sample"]
                    if any(indicator in a.lower() for indicator in arg_indicators):
                        mutatables['tiff_call_buffers'].append(
                            (fname, i, a, self.current_function, call_code)
                        )
                        
                # Check for compression-related functions
                if 'Compression' in call_code or 'compress' in call_code.lower():
                    mutatables['compression_fields'].append((fname, call_code, self.current_function))

       

        def visit_ArrayRef(self, node):
            """Capture array accesses that might be overflow targets"""
            array_code = get_node_actual_code(node)
            array_name = get_node_actual_code(getattr(node, 'name', None))
            subscript = get_node_actual_code(getattr(node, 'subscript', None))
            
            # Track array accesses in buffer-like variables
            buffer_vars = ["buf", "data", "buffer", "scanline", "strip", "tile"]
            if any(buf in array_name.lower() for buf in buffer_vars):
                mutatables['pointer_operations'].append(
                    (array_name, f"[{subscript}]", "array_access", self.current_function, array_code)
                )
            
            self.generic_visit(node)

        def visit_FileAST(self, node):
            """Capture file operations (TIFFOpen, fopen, etc.)"""
            self.generic_visit(node)

    Visitor().visit(ast)
    
    return mutatables


def build_tiff_prompt(c_code, mutatables, rag_context=None):
  
    context_text = rag_context or ""
    
    # Extract specific TIFF metadata values for the prompt
    tiff_metadata = {}
    for tag, value, category, _ in mutatables.get('tiff_tags', []):
        if category in ['dimension', 'compression', 'tifftag']:
            tiff_metadata[tag.upper()] = value
    
    # Summary of discovered TIFF fields
    summary_lines = []
    if mutatables.get('tiff_tags'):
        summary_lines.append("TIFF Tags: " + ", ".join([f"{tag}={val}" for tag, val, _, _ in mutatables['tiff_tags'][:8]]))
    if mutatables.get('tiff_functions'):
        summary_lines.append("TIFF Functions: " + ", ".join([f[0] for f in mutatables['tiff_functions'][:5]]))
    if mutatables.get('compression_fields'):
        comp_info = [f"{name}:{desc}" for name, desc, _ in mutatables['compression_fields']]
        if comp_info:
            summary_lines.append("Compression: " + ", ".join(comp_info))

    mut_summary = "\n".join(summary_lines) if summary_lines else "TIFF processing code detected"
    prompt = f'''
You're a vulnerability researcher focusing on libtiff crash discovery. Your task is to modify the existing PoC input and generate variants 
You must preserve input structure and semantics. Do not invent new formats or logic. All changes must be minimal and localized. No need to execute from your end.

{context_text}

Mutation summary:
{mut_summary}

Given the following PoC in tiff format:

```c
{c_code.strip()}


```

Generate C-based PoC variants that mutate:
- segmentation faults
- buffer overflows
- abort
- core dumped


Output at least 3  C codes variant to generate tiff file in this format:
```c
// Variant 1 - [short explanation]
<variant code>

// Variant 2 - [short explanation]
<variant code>

// Variant 3 - [short explanation]
<variant code>
```

Exploration Mode:


Variant constraints:

    - Only modify existing numeric values
    - Apply small, localized changes 
    - Do not add or remove required fields
    - Do not randomize the input
    - Do not fix/handle the vulnerability

Now you’ll analyze the PoC and here’s your tasks

    - Generate the variant
    - Change the numeric values
    - Each variant must use a different mutation pattern
    - Output each variant clearly separated
    - For each variant, explain:
    #Numeric fields changed
    #Why parsing should still succeed
    #Expected new impact

'''
    print("\n=================== libtiff Prompt Template ===================")
    print("Mutatables detected:", {k: len(v) for k, v in mutatables.items()})
    return prompt



def extract_libtiff_features_from_code(c_code):
    mutatables = extract_mutatable_fields_from_ast(c_code)
    # build a field list for RAG queries (take first element of each tuple)
    fields = []
    fields += [tag for tag, _, _, _ in mutatables.get('tiff_tags', [])]

# Add only TIFF/format related keywords
    fields += ["TIFF", "libtiff", "image format", "raster graphics"]

# Add compression-specific keywords if detected
    if "jbg_" in c_code.lower():
        fields += ["JBIG", "bitmap compression", "fax compression"]
    elif "jpeg" in c_code.lower() or "jpg" in c_code.lower():
        fields += ["JPEG", "lossy compression", "DCT"]
    elif "lzw" in c_code.lower():
        fields += ["LZW", "dictionary compression"]
    elif "deflate" in c_code.lower() or "zlib" in c_code.lower():
        fields += ["DEFLATE", "zip compression"]

    # Add general image processing terms
    fields += ["image processing", "file format", "parsing", "decoding"]

    # Try to get RAG context if available
    rag_context = ""
    try:
    # Since RAG_module.py seems to have wrong content, we'll skip it
    # or you need to provide the correct RAG module
        pass
    except ImportError:
        print("RAG module not available, continuing without RAG context")
    except Exception as e:
        print(f"RAG context failed: {e}")

    prompt = build_tiff_prompt(c_code, mutatables, rag_context)

    return {
        "mutatables": mutatables,
        "prompt_template": prompt,
        "tiff_metadata": {tag: val for tag, val, _, _ in mutatables.get('tiff_tags', [])}   
    }

if __name__ == '__main__':
    c_code =  """
Magic: 0x4949 <little-endian> Version: 0x2a <ClassicTIFF>
Directory 0: offset 98 (0x62) next 0 (0)
ImageWidth (256) SHORT (3) 1<32>
ImageLength (257) SHORT (3) 1<32800>
BitsPerSample (258) SHORT (3) 1<4>
Compression (259) SHORT (3) 1<8>
SamplesPerPixel (277) SHORT (3) 1<3>
FillOrder (266) SHORT (3) 1<1>
DocumentName (269) ASCII (2) 15<not_kitty.tiff\0>
StripOffsets (273) LONG (4) 1<8>
Orientation (274) SHORT (3) 1<1>
SamplesPerPixel (277) SHORT (3) 1<1>
RowsPerStrip (278) SHORT (3) 1<32>
StripByteCounts (279) LONG (4) 1<89>
XResolution (282) RATIONAL (5) 1<72>
YResolution (283) RATIONAL (5) 1<72>
PlanarConfig (284) SHORT (3) 1<1>
ResolutionUnit (296) SHORT (3) 1<1>
PageNumber (297) SHORT (3) 2<0 1>
TransferFunction (301) SHORT (3) 48<26214 65535 0 13107 39321 0 0 0 0 0 0 0 0 0 0 0 52428 65535 0 39321 65535 0 0 0 ...>
"""
    result = extract_libtiff_features_from_code(c_code)