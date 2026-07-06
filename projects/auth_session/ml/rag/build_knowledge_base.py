import pandas as pd
import os
try:
    from langchain_huggingface import HuggingFaceEmbeddings
except ImportError:
    from langchain_community.embeddings import HuggingFaceEmbeddings

try:
    from langchain_community.vectorstores import FAISS
except ImportError:
    from langchain.vectorstores import FAISS

try:
    from langchain_community.document_loaders import CSVLoader, PyPDFLoader
except ImportError:
    from langchain.document_loaders import CSVLoader, PyPDFLoader

try:
    from langchain_text_splitters import CharacterTextSplitter
except ImportError:
    from langchain.text_splitter import CharacterTextSplitter

# Define paths relative to this script
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, '../../../../'))

# Define potential dataset paths
# We look for datasets in various likely locations based on the project structure
datasets_to_check = [
    os.path.join(SCRIPT_DIR, '../../data/idor_dataset.csv'),  # projects/auth_session/data/idor_dataset.csv
    os.path.join(PROJECT_ROOT, 'projects/xss_detection/data/xss_response_dataset.csv'),
    os.path.join(PROJECT_ROOT, 'projects/sql_injection/data/feature_dataset.csv'),
    # Fallback/Placeholder paths
    os.path.join(SCRIPT_DIR, '../broken_access_control_dataset.csv'),
    'ml/idor_dataset.csv', # Original path from user, just in case
]

documents = []
splitter = CharacterTextSplitter(chunk_size=500, chunk_overlap=50)

print("Loading datasets...")
for csv_path in datasets_to_check:
    if os.path.exists(csv_path):
        print(f"Loading {csv_path}...")
        try:
            loader = CSVLoader(file_path=csv_path, encoding='utf-8')
            docs = loader.load()
            split_docs = splitter.split_documents(docs)
            documents.extend(split_docs)
            print(f"  Loaded {len(split_docs)} documents.")
        except Exception as e:
            print(f"  Error loading {csv_path}: {e}")
            # Try with different encoding if utf-8 fails
            try:
                loader = CSVLoader(file_path=csv_path, encoding='latin-1')
                docs = loader.load()
                split_docs = splitter.split_documents(docs)
                documents.extend(split_docs)
                print(f"  Loaded {len(split_docs)} documents (latin-1).")
            except Exception as e2:
                print(f"  Failed to load {csv_path} with latin-1: {e2}")

    else:
        # print(f"Skipping {csv_path} (not found)")
        pass

# Add external docs (e.g., OWASP PDF in docs/)
owasp_path = os.path.join(PROJECT_ROOT, 'docs/owasp_top_10.pdf')
if os.path.exists(owasp_path):
    print(f"Loading {owasp_path}...")
    try:
        owasp_loader = PyPDFLoader(owasp_path)
        owasp_docs = owasp_loader.load()
        split_owasp = splitter.split_documents(owasp_docs)
        documents.extend(split_owasp)
        print(f"  Loaded {len(split_owasp)} documents from PDF.")
    except Exception as e:
        print(f"  Error loading PDF: {e}")
else:
    print(f"OWASP PDF not found at {owasp_path}, skipping.")

if not documents:
    print("No documents loaded! Please check your dataset paths.")
    exit(1)

print(f"Total documents to index: {len(documents)}")

# Embed and store
print("Initializing embeddings (this may take a moment)...")
try:
    embeddings = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")
    
    print("Creating vector store...")
    vectorstore = FAISS.from_documents(documents, embeddings)
    
    save_path = os.path.join(SCRIPT_DIR, "vectorstore")
    vectorstore.save_local(save_path)
    print(f"Knowledge base built successfully! Saved to {save_path}")
except Exception as e:
    print(f"Error creating/saving vector store: {e}")
