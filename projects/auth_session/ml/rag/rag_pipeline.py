import os
import sys

try:
    from langchain_huggingface import HuggingFaceEmbeddings
except ImportError:
    from langchain_community.embeddings import HuggingFaceEmbeddings

try:
    from langchain_community.vectorstores import FAISS
except ImportError:
    from langchain.vectorstores import FAISS

try:
    from langchain_huggingface import HuggingFaceEndpoint
except ImportError:
    from langchain_community.llms import HuggingFaceEndpoint

from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain_core.runnables import RunnablePassthrough, RunnableParallel

# Define paths relative to this script
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
VECTORSTORE_PATH = os.path.join(SCRIPT_DIR, "vectorstore")

# Custom prompt for security context
prompt_template = """Use the following context to answer the question about web vulnerabilities.
Context: {context}
Question: {question}
Answer clearly, including vulnerability details, examples, and mitigation steps:"""

PROMPT = PromptTemplate(template=prompt_template, input_variables=["context", "question"])

def format_docs(docs):
    return "\n\n".join(doc.page_content for doc in docs)

def load_rag_chain():
    # Ensure vector store exists
    if not os.path.exists(VECTORSTORE_PATH):
        raise FileNotFoundError(f"Vector store not found at {VECTORSTORE_PATH}. Please run build_knowledge_base.py first.")

    embeddings = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")
    
    # Load vector store
    vectorstore = FAISS.load_local(VECTORSTORE_PATH, embeddings, allow_dangerous_deserialization=True)
    
    # Check for API Token
    if "HUGGINGFACEHUB_API_TOKEN" not in os.environ:
        print("Warning: HUGGINGFACEHUB_API_TOKEN not found in environment variables.")
        print("Please set it to use the LLM generation capabilities.")
        # We can return a partial chain or fail later
    
    # Initialize LLM
    try:
        llm = HuggingFaceEndpoint(
            repo_id="google/flan-t5-large", 
            temperature=0.5, 
            max_new_tokens=512
        )
    except Exception as e:
        print(f"Error initializing LLM: {e}")
        # Return a dummy LLM or fail?
        raise
    
    retriever = vectorstore.as_retriever(search_kwargs={"k": 5})

    # RAG Chain with Source Retrieval
    # We use RunnableParallel to pass retrieved docs to the output
    rag_chain_from_docs = (
        RunnablePassthrough.assign(context=(lambda x: format_docs(x["context"])))
        | PROMPT
        | llm
        | StrOutputParser()
    )

    rag_chain_with_source = RunnableParallel(
        {"context": retriever, "question": RunnablePassthrough()}
    ).assign(answer=rag_chain_from_docs)

    return rag_chain_with_source

def generate_augmented_report(query):
    try:
        chain = load_rag_chain()
        result = chain.invoke(query)
            
        return {
            "generated_report": result['answer'],
            "sources": [doc.metadata for doc in result['context']]  # For traceability
        }
    except Exception as e:
        error_repr = repr(e)
        error_str = str(e) if str(e) else error_repr
        
        # Fallback to local Vectorstore (no LLM API required)
        try:
            embeddings = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")
            vectorstore = FAISS.load_local(VECTORSTORE_PATH, embeddings, allow_dangerous_deserialization=True)
            docs = vectorstore.similarity_search(query, k=3)
            
            fallback_text = "⚠️ **AI Generation Unavailable** — *Displaying relevant documentation from local knowledge base instead.*\n\n---\n\n"
            for i, doc in enumerate(docs):
                fallback_text += f"**Source {i+1}**: `{doc.metadata.get('source', 'Security Documentation')}`\n\n> {doc.page_content.replace(chr(10), chr(10)+'> ')}\n\n"
                
            return {
                "generated_report": fallback_text,
                "sources": [doc.metadata for doc in docs],
                "error": error_str
            }
        except Exception as fallback_e:
            return {
                "error": error_str,
                "generated_report": f"Failed to generate report: {error_str}\n\nFallback also failed: {repr(fallback_e)}",
                "sources": []
            }

if __name__ == "__main__":
    # Simple test if run directly
    test_query = "What is IDOR?"
    print(f"Testing RAG pipeline with query: '{test_query}'")
    result = generate_augmented_report(test_query)
    print("\n--- Report ---")
    print(result.get("generated_report"))
    print("\n--- Sources ---")
    print(result.get("sources"))
