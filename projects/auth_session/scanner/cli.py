import click
from scanner.scanner import Scanner

@click.command()
@click.option('--input-file', required=True, help='Input file for scanning')
@click.option('--use-ml', is_flag=True, help='Enable ML detection')
def scan(input_file, use_ml):
    scanner = Scanner(input_file)
    results = scanner.run(use_ml=use_ml)
    for result in results:
        ml_label = result.get('ml_label', 'N/A')
        ml_conf = result.get('ml_confidence', 'N/A')
        print(f"Request: {result['request']}, ML: {ml_label} (Conf: {ml_conf})")

if __name__ == '__main__':
    scan()