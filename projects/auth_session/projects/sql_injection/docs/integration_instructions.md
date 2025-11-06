# Integration Instructions

## Running with ML
python scanner/cli.py --input-file <file> --use-ml

Results include 'ml_label' (0=safe, 1=malicious) and 'ml_confidence'.

## Config
- Model: projects/sql_injection/models/best_model.pkl
- For batching/high load: See performance notes in code.