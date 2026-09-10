import os
import re
from bs4 import BeautifulSoup, NavigableString
from deep_translator import GoogleTranslator

def translate_file(filepath):
    print(f"Translating {filepath}...")
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    # Preserve handlebars tags by converting them to comments
    content = re.sub(r'\{\{define\s+"([^"]+)"\}\}', r'<!--DEFINE \1-->', content)
    content = re.sub(r'\{\{end\}\}', r'<!--END-->', content)

    soup = BeautifulSoup(content, 'html.parser')
    translator = GoogleTranslator(source='es', target='en')
    
    # Collect all text nodes
    text_nodes = []
    for element in soup.descendants:
        if isinstance(element, NavigableString):
            text = str(element).strip()
            # Only translate if there's actual text
            if text and not element.parent.name in ['style', 'script']:
                # Skip HTML comments
                if isinstance(element, type(BeautifulSoup('', 'html.parser').string)) and not hasattr(element, 'name') and type(element).__name__ == 'Comment':
                  continue
                text_nodes.append(element)
    
    # Batch translation
    print(f"  Found {len(text_nodes)} text nodes.")
    batch_size = 10
    for i in range(0, len(text_nodes), batch_size):
        batch = text_nodes[i:i+batch_size]
        texts_to_translate = [str(node).strip() for node in batch]
        
        try:
            translated_texts = translator.translate_batch(texts_to_translate)
            for node, trans in zip(batch, translated_texts):
                node.replace_with(trans + " ")
        except Exception as e:
            print(f"  Error batch translating, falling back to single: {e}")
            for node in batch:
                try:
                    txt = str(node).strip()
                    if len(txt) > 0:
                        trans = translator.translate(txt)
                        node.replace_with(trans + " ")
                except Exception:
                    pass

    new_content = str(soup)
    # Restore handlebars
    new_content = re.sub(r'<!--DEFINE (.*?)-->', r'{{define "\1_en"}}', new_content)
    new_content = re.sub(r'<!--END-->', r'{{end}}', new_content)

    new_filepath = filepath.replace('.hbs', '_en.hbs')
    with open(new_filepath, 'w', encoding='utf-8') as f:
        f.write(new_content)
    print(f"Saved {new_filepath}")

files = [
    'certauthserver/views/contract/1_estipulaciones.hbs',
    'certauthserver/views/contract/2_anexo_1.hbs',
    'certauthserver/views/contract/3_anexo_2.hbs',
    'certauthserver/views/contract/3_anexo_3.hbs',
]

for f in files:
    if os.path.exists(f):
        translate_file(f)
    else:
        print(f"File {f} not found!")

