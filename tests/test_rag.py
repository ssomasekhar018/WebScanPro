import unittest
import os
import sys

# Add project root to path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, '../'))
sys.path.append(PROJECT_ROOT)

from projects.auth_session.ml.rag.rag_pipeline import generate_augmented_report

class TestRAGPipeline(unittest.TestCase):
    
    def test_rag_generation(self):
        print("\nTesting RAG Generation...")
        
        # Skip if no token (to avoid failure in automated environments without secrets)
        if "HUGGINGFACEHUB_API_TOKEN" not in os.environ:
            print("Skipping test_rag_generation: HUGGINGFACEHUB_API_TOKEN not set")
            return

        query = "Explain IDOR vulnerability with mitigation"
        result = generate_augmented_report(query)
        
        # Check structure
        self.assertIn("generated_report", result)
        self.assertIn("sources", result)
        
        # Check content quality (basic checks)
        report_lower = result["generated_report"].lower()
        self.assertTrue(len(report_lower) > 20, "Report is too short")
        
        # Check if sources were retrieved
        self.assertTrue(len(result["sources"]) > 0, "No sources retrieved")
        
        print("Test passed!")

if __name__ == '__main__':
    unittest.main()
