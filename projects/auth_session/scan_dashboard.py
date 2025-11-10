#!/usr/bin/env python3
"""
IDOR Scan Results Dashboard Generator
Generates a quick summary dashboard from scan results CSV files
"""

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os
import glob
from datetime import datetime

def generate_dashboard():
    """Generate a comprehensive dashboard from scan results"""
    
    # Find all scan result files
    scan_files = glob.glob("output/*scan*.csv")
    
    if not scan_files:
        print("No scan result files found in output/ directory")
        return
    
    # Load and combine all results
    all_results = []
    for file in scan_files:
        try:
            df = pd.read_csv(file)
            if not df.empty:
                all_results.append(df)
                print(f"Loaded {len(df)} results from {os.path.basename(file)}")
        except Exception as e:
            print(f"Error loading {file}: {e}")
    
    if not all_results:
        print("No valid scan results found")
        return
    
    # Combine all results
    combined_df = pd.concat(all_results, ignore_index=True)
    
    print(f"\n=== IDOR SCAN DASHBOARD ===")
    print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Total Tests: {len(combined_df)}")
    print(f"Applications Tested: {combined_df['application'].nunique()}")
    
    # Application breakdown
    print(f"\n=== APPLICATION BREAKDOWN ===")
    app_summary = combined_df.groupby('application').agg({
        'ml_prediction': ['count', 'sum'],
        'ml_probability': 'mean',
        'status_code': lambda x: x.value_counts().to_dict()
    }).round(3)
    
    for app in combined_df['application'].unique():
        app_data = combined_df[combined_df['application'] == app]
        total_tests = len(app_data)
        anomalous = app_data['ml_prediction'].sum()
        normal = total_tests - anomalous
        avg_confidence = app_data['ml_probability'].mean()
        
        print(f"\n{app}:")
        print(f"  Total Tests: {total_tests}")
        print(f"  Normal: {normal} ({normal/total_tests*100:.1f}%)")
        print(f"  Anomalous: {anomalous} ({anomalous/total_tests*100:.1f}%)")
        print(f"  Avg Confidence: {avg_confidence:.3f}")
        
        # Status code breakdown
        status_codes = app_data['status_code'].value_counts()
        print(f"  Status Codes: {dict(status_codes)}")
    
    # ML Model Performance
    print(f"\n=== ML MODEL PERFORMANCE ===")
    total_anomalous = combined_df['ml_prediction'].sum()
    total_normal = len(combined_df) - total_anomalous
    
    print(f"Overall Classification:")
    print(f"  Normal: {total_normal} ({total_normal/len(combined_df)*100:.1f}%)")
    print(f"  Anomalous: {total_anomalous} ({total_anomalous/len(combined_df)*100:.1f}%)")
    
    # Confidence distribution
    confidence_ranges = pd.cut(combined_df['ml_probability'], 
                              bins=[0, 0.3, 0.7, 1.0], 
                              labels=['Low (0-0.3)', 'Medium (0.3-0.7)', 'High (0.7-1.0)'])
    print(f"\nConfidence Distribution:")
    for range_label, count in confidence_ranges.value_counts().items():
        print(f"  {range_label}: {count} ({count/len(combined_df)*100:.1f}%)")
    
    # Response analysis
    print(f"\n=== RESPONSE ANALYSIS ===")
    print(f"Response Length Statistics:")
    print(f"  Min: {combined_df['response_length'].min()}")
    print(f"  Max: {combined_df['response_length'].max()}")
    print(f"  Mean: {combined_df['response_length'].mean():.1f}")
    print(f"  Median: {combined_df['response_length'].median():.1f}")
    
    # Test type breakdown
    print(f"\n=== TEST TYPE BREAKDOWN ===")
    test_types = combined_df['test_type'].value_counts()
    for test_type, count in test_types.items():
        print(f"  {test_type}: {count}")
    
    # Time analysis
    if 'timestamp' in combined_df.columns:
        combined_df['timestamp'] = pd.to_datetime(combined_df['timestamp'])
        time_range = combined_df['timestamp'].max() - combined_df['timestamp'].min()
        print(f"\n=== TIME ANALYSIS ===")
        print(f"Scan Duration: {time_range}")
        print(f"Start Time: {combined_df['timestamp'].min()}")
        print(f"End Time: {combined_df['timestamp'].max()}")
    
    # Generate summary statistics file
    summary_file = f"output/scan_dashboard_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    
    # Capture the printed output to file
    import sys
    from io import StringIO
    
    # Redirect stdout to capture the dashboard
    old_stdout = sys.stdout
    sys.stdout = buffer = StringIO()
    
    # Re-run the dashboard generation (this will be captured)
    print(f"=== IDOR SCAN DASHBOARD ===")
    print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Total Tests: {len(combined_df)}")
    print(f"Applications Tested: {combined_df['application'].nunique()}")
    
    for app in combined_df['application'].unique():
        app_data = combined_df[combined_df['application'] == app]
        total_tests = len(app_data)
        anomalous = app_data['ml_prediction'].sum()
        normal = total_tests - anomalous
        avg_confidence = app_data['ml_probability'].mean()
        
        print(f"\n{app}:")
        print(f"  Total Tests: {total_tests}")
        print(f"  Normal: {normal} ({normal/total_tests*100:.1f}%)")
        print(f"  Anomalous: {anomalous} ({anomalous/total_tests*100:.1f}%)")
        print(f"  Avg Confidence: {avg_confidence:.3f}")
    
    # Restore stdout and write to file
    sys.stdout = old_stdout
    dashboard_content = buffer.getvalue()
    
    with open(summary_file, 'w') as f:
        f.write(dashboard_content)
    
    print(f"\n=== DASHBOARD SAVED ===")
    print(f"Dashboard saved to: {summary_file}")
    
    # Generate CSV summary for further analysis
    csv_summary = combined_df.groupby(['application', 'test_type']).agg({
        'ml_prediction': ['count', 'sum', 'mean'],
        'ml_probability': 'mean',
        'response_length': 'mean'
    }).round(3)
    
    csv_file = f"output/scan_metrics_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    csv_summary.to_csv(csv_file)
    print(f"CSV metrics saved to: {csv_file}")
    
    return combined_df

def generate_visualizations():
    """Generate visualization charts from scan results"""
    try:
        # Find the most recent comprehensive scan file
        scan_files = glob.glob("output/comprehensive_idor_scan_*.csv")
        if not scan_files:
            print("No comprehensive scan files found for visualization")
            return
        
        latest_file = max(scan_files, key=os.path.getctime)
        df = pd.read_csv(latest_file)
        
        # Set up the plot style
        plt.style.use('seaborn-v0_8')
        fig, axes = plt.subplots(2, 2, figsize=(15, 10))
        fig.suptitle('IDOR Scan Results Dashboard', fontsize=16, fontweight='bold')
        
        # 1. Application Distribution
        app_counts = df['application'].value_counts()
        axes[0,0].pie(app_counts.values, labels=app_counts.index, autopct='%1.1f%%')
        axes[0,0].set_title('Tests by Application')
        
        # 2. ML Classification Results
        ml_counts = df['ml_label'].value_counts()
        axes[0,1].bar(ml_counts.index, ml_counts.values, color=['green', 'red'])
        axes[0,1].set_title('ML Classification Results')
        axes[0,1].set_ylabel('Count')
        
        # 3. Response Length Distribution
        axes[1,0].hist(df['response_length'], bins=10, alpha=0.7, color='blue')
        axes[1,0].set_title('Response Length Distribution')
        axes[1,0].set_xlabel('Response Length')
        axes[1,0].set_ylabel('Frequency')
        
        # 4. Status Code Distribution
        status_counts = df['status_code'].value_counts()
        axes[1,1].bar(status_counts.index.astype(str), status_counts.values, color='orange')
        axes[1,1].set_title('HTTP Status Code Distribution')
        axes[1,1].set_xlabel('Status Code')
        axes[1,1].set_ylabel('Count')
        
        plt.tight_layout()
        
        # Save the plot
        plot_file = f"output/scan_dashboard_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        plt.savefig(plot_file, dpi=300, bbox_inches='tight')
        plt.show()
        
        print(f"Visualization saved to: {plot_file}")
        
    except Exception as e:
        print(f"Error generating visualizations: {e}")

if __name__ == "__main__":
    print("Generating IDOR Scan Dashboard...")
    
    # Generate text dashboard
    df = generate_dashboard()
    
    # Generate visualizations
    try:
        generate_visualizations()
    except Exception as e:
        print(f"Could not generate visualizations: {e}")
        print("Text dashboard generated successfully.")
    
    print("\nDashboard generation complete!")