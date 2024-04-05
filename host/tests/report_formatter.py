from json import load as json_load
from os import path as os_path
from pandas import DataFrame

__report_path__ = os_path.join(os_path.split(__file__)[0], 'results', '.report.json')
__server_log__ = os_path.join(os_path.split(__file__)[0], 'results', 'server.log')
__outfile__ = os_path.join(os_path.split(__file__)[0], 'results', 'performance.log')


def _parse_args(cmd=None):
    import argparse
    parser = argparse.ArgumentParser(
        prog=os_path.split(__file__)[1],
        description="Transform JSON test reports into a more readable format"
    )
    parser.add_argument(
        '-m', '--missing',
        action='store_true',
        default=False,
        help='Includes the preview of missed lines for each covered file'
    )
    parser.add_argument(
        '-r', '--report',
        help='Path to JSON report. Defaults to host/tests/results/.report.json'
    )
    parser.add_argument(
        '-l', '--server-log',
        help='Path to server log. Defaults to host/tests/results/server.log'
    )
    parser.add_argument(
        '-o', '--output',
        help='Path to output report generated. Defaults to host/tests/results/performance.log'
    )
    return parser.parse_args(cmd)


if __name__ == '__main__':
    args = _parse_args()
    buffer = list()
    df_report_summary = DataFrame(columns=['file', 'cov %', '# missed lines'])
    
    with open(args.report if args.report is not None else __report_path__, 'r') as reportfile:
        print(f"[*] Parsing Pytest report ({reportfile.name.split('tee-integration/')[1]})...")
        report = json_load(reportfile)
    for file_name in report['files']:
        file_index = report['files'][file_name]
        df_report_summary.loc[len(df_report_summary)] = [
            file_name,
            file_index['summary']['percent_covered_display'],
            file_index['summary']['missing_lines']
        ]
        # Get missing lines if necessary
        if args.missing and file_index['summary']['missing_lines'] > 0:
            buffer.append(f"\n{file_name} - {file_index['summary']['missing_lines']} missed lines")
            if file_name.startswith('test_'):
                _fpath = os_path.join(os_path.split(__file__)[0], file_name)
            else:
                _fpath = os_path.join(os_path.split(__file__)[0], '..', 'gicp_api', file_name)
            with open(_fpath, 'r', encoding='utf-8') as sourcefile:
                source_code = sourcefile.readlines()
                for ln in file_index['missing_lines']:
                    try:
                        buffer.append(f"  {ln}: {source_code[ln - 1].strip()}")
                    except IndexError:
                        buffer.append(f"{ln}: ERROR RETRIEVING LINE")
    df_report_summary.loc[len(df_report_summary)] = [
        'TOTAL',
        report['totals']['percent_covered_display'],
        report['totals']['missing_lines']
    ]
    with open(args.output if args.output is not None else __outfile__, 'a', encoding='utf-8') as outfile:
        outfile.write(f"{'-' * 20}\nTEST COVERAGE SUMMARY\n\n" + df_report_summary.to_string(index=False) + '\n')
        if args.missing and len(buffer) > 0:
            outfile.write(f"\n\n- Missing lines -\n" + '\n'.join(buffer) + '\n')
        # Include the server logs in the test report
        outfile.write(f"{'-' * 20}\nSERVER LOGS\n\n```shell\n")
        outfile.writelines(open(args.server_log if args.server_log is not None else __server_log__, 'r').readlines())
        outfile.write(f"```\n")
        print(f"[*] Formatted report generated successfully ({outfile.name.split('tee-integration/')[1]})")
