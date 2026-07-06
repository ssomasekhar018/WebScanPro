import os
import sys

# Add project root to path if needed
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, '../../../../'))
sys.path.append(PROJECT_ROOT)

from projects.auth_session.ml.rag.rag_pipeline import generate_augmented_report

def test_pipeline():
    print("Testing RAG Pipeline...")
    
    # Check for token
    if "HUGGINGFACEHUB_API_TOKEN" not in os.environ:
        print("\n[WARN] HUGGINGFACEHUB_API_TOKEN is not set. Generation will likely fail.")
        print("Please set it via: $env:HUGGINGFACEHUB_API_TOKEN='your_token'")
    
    query = "Explain IDOR vulnerability with an example from the dataset"
    print(f"\nQuery: {query}")
    
    result = generate_augmented_report(query)
    
    if "error" in result:
        print(f"\n[ERROR] Pipeline failed: {result['error']}")
        if "HUGGINGFACEHUB_API_TOKEN" not in os.environ:
            print("Tip: This is expected if you haven't set your Hugging Face API token.")
    else:
        print("\n[SUCCESS] Report Generated:")
        print("-" * 50)
        print(result["generated_report"])
        print("-" * 50)
        
        print("\nSources Used:")
        for i, source in enumerate(result["sources"]):
            print(f"{i+1}. {source.get('source', 'Unknown source')}")

if __name__ == "__main__":
    test_pipeline()
