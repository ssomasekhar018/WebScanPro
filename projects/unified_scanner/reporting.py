"""
Reporting module for the unified vulnerability scanner.
Handles result aggregation and report generation.
"""

import os
import json
import logging
import pandas as pd
from datetime import datetime
from tabulate import tabulate

logger = logging.getLogger(__name__)

class VulnerabilityReporter:
    def __init__(self, output_file=None):
        self.output_file = output_file
        self.results = []
    
    def add_result(self, result):
        """Add a scan result to the report."""
        self.results.append(result)
    
    def get_summary(self):
        """Generate a summary of scan results."""
        summary = {
            "total_urls": len(self.results),
            "xss_detected": sum(1 for r in self.results if r.get("xss", {}).get("is_vulnerable", False)),
            "sqli_detected": sum(1 for r in self.results if r.get("sqli", {}).get("is_vulnerable", False)),
            "high_risk_urls": sum(1 for r in self.results if self._calculate_risk_level(r) == "High"),
            "medium_risk_urls": sum(1 for r in self.results if self._calculate_risk_level(r) == "Medium"),
            "low_risk_urls": sum(1 for r in self.results if self._calculate_risk_level(r) == "Low"),
            "timestamp": datetime.now().isoformat()
        }
        return summary
        
    def generate_report(self, results=None):
        """Generate a JSON report from scan results."""
        if results:
            self.results = results
            
        if not self.results:
            logger.warning("No results to report")
            return False
            
        # Ensure output directory exists
        if self.output_file:
            os.makedirs(os.path.dirname(self.output_file), exist_ok=True)
            
        # Create report structure
        report = {
            "scan_summary": self.get_summary(),
            "scan_results": self.results
        }
        
        # Write report to file
        if self.output_file:
            try:
                with open(self.output_file, 'w') as f:
                    json.dump(report, f, indent=2)
                logger.info(f"Report saved to {self.output_file}")
                return True
            except Exception as e:
                logger.error(f"Failed to save report: {str(e)}")
                return False
                
        return report
    
    def _calculate_risk_level(self, result):
        """Calculate risk level based on vulnerability probabilities."""
        xss_prob = result.get("xss", {}).get("probability", 0)
        sqli_prob = result.get("sqli", {}).get("probability", 0)
        
        # Determine risk level based on highest probability
        max_prob = max(xss_prob, sqli_prob)
        
        if max_prob >= 0.8:
            return "High"
        elif max_prob >= 0.5:
            return "Medium"
        else:
            return "Low"
    
    def save_json_report(self, output_file=None):
        """Save scan results to a JSON file."""
        if output_file:
            self.output_file = output_file
            
        if not self.output_file:
            logger.error("No output file specified for JSON report")
            return False
            
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(self.output_file), exist_ok=True)
            
            # Prepare report data
            report_data = {
                "summary": self.get_summary(),
                "results": self.results
            }
            
            # Write to file
            with open(self.output_file, 'w') as f:
                json.dump(report_data, f, indent=4)
                
            logger.info(f"JSON report saved to {self.output_file}")
            return True
        except Exception as e:
            logger.error(f"Failed to save JSON report: {str(e)}")
            return False
    
    def save_csv_report(self, output_file=None):
        """Save scan results to a CSV file."""
        if not output_file and not self.output_file:
            logger.error("No output file specified for CSV report")
            return False
            
        csv_file = output_file or self.output_file.replace('.json', '.csv')
        
        try:
            # Flatten results for CSV format
            flattened_results = []
            for result in self.results:
                flat_result = {
                    "url": result.get("url", ""),
                    "xss_vulnerable": result.get("xss", {}).get("is_vulnerable", False),
                    "xss_probability": result.get("xss", {}).get("probability", 0),
                    "sqli_vulnerable": result.get("sqli", {}).get("is_vulnerable", False),
                    "sqli_probability": result.get("sqli", {}).get("probability", 0),
                    "risk_level": self._calculate_risk_level(result)
                }
                flattened_results.append(flat_result)
                
            # Convert to DataFrame and save
            df = pd.DataFrame(flattened_results)
            df.to_csv(csv_file, index=False)
            
            logger.info(f"CSV report saved to {csv_file}")
            return True
        except Exception as e:
            logger.error(f"Failed to save CSV report: {str(e)}")
            return False
    
    def print_console_summary(self):
        """Print a summary table to the console."""
        if not self.results:
            print("No scan results to display")
            return
            
        # Prepare table data
        table_data = []
        for result in self.results:
            url = result.get("url", "")
            xss_result = f"{'Yes' if result.get('xss', {}).get('is_vulnerable', False) else 'No'} ({result.get('xss', {}).get('probability', 0):.2f})"
            sqli_result = f"{'Yes' if result.get('sqli', {}).get('is_vulnerable', False) else 'No'} ({result.get('sqli', {}).get('probability', 0):.2f})"
            risk_level = self._calculate_risk_level(result)
            
            table_data.append([url, xss_result, sqli_result, risk_level])
            
        # Print table
        headers = ["URL", "XSS Detected", "SQLi Detected", "Risk Level"]
        print("\nScan Results Summary:")
        print(tabulate(table_data, headers=headers, tablefmt="grid"))
        
        # Print overall summary
        summary = self.get_summary()
        print(f"\nTotal URLs scanned: {summary['total_urls']}")
        print(f"XSS vulnerabilities detected: {summary['xss_detected']}")
        print(f"SQLi vulnerabilities detected: {summary['sqli_detected']}")
        print(f"High risk URLs: {summary['high_risk_urls']}")
        print(f"Medium risk URLs: {summary['medium_risk_urls']}")
        print(f"Low risk URLs: {summary['low_risk_urls']}")
        print(f"Scan completed at: {summary['timestamp']}")