import os
try:
    from langchain_huggingface import HuggingFaceEmbeddings
except ImportError:
    from langchain_community.embeddings import HuggingFaceEmbeddings

try:
    from langchain_community.vectorstores import FAISS
except ImportError:
    from langchain.vectorstores import FAISS

# Define paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
VECTORSTORE_PATH = os.path.join(SCRIPT_DIR, "vectorstore")

print(f"Loading vector store from {VECTORSTORE_PATH}...")

try:
    embeddings = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")
    vectorstore = FAISS.load_local(VECTORSTORE_PATH, embeddings, allow_dangerous_deserialization=True)
    
    # Test query
    query = "IDOR vulnerability in profile"
    print(f"\nQuerying: '{query}'")
    
    docs = vectorstore.similarity_search(query, k=3)
    
    print(f"\nFound {len(docs)} documents:")
    for i, doc in enumerate(docs):
        print(f"\n--- Result {i+1} ---")
        print(doc.page_content[:200] + "...") # Print first 200 chars
        print(f"Source: {doc.metadata.get('source', 'Unknown')}")

except Exception as e:
    print(f"Error testing retrieval: {e}")
