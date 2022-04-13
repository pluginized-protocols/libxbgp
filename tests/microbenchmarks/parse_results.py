import csv


def main(str_file: str):
    parsed_csv = {}
    with open(str_file, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            fn_name = row['fn_name']
            if fn_name not in fn_name:
                parsed_csv[fn_name] = {
                    'sample': []
                }
            parsed_csv[fn_name]['sample'].append()