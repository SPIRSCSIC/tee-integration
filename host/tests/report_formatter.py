import argparse
from json import load as json_load
from pathlib import Path

from pandas import DataFrame


CWD = Path(__file__).parent
__report_path__ = CWD / "results/.report.json"
__server_log__ = CWD / "results/server.log"
__outfile__ = CWD / "results/performance.log"


def _format_coverage(rdata):
    buffer = list()
    df_report_summary = DataFrame(
        columns=["file", "cov %", "# missed lines"]
    )

    for file_name in rdata["files"]:
        file_index = rdata["files"][file_name]
        df_report_summary.loc[len(df_report_summary)] = [
            file_name,
            file_index["summary"]["percent_covered_display"],
            file_index["summary"]["missing_lines"],
        ]
        # Get missing lines if necessary
        if (
            args.missing
            and file_index["summary"]["missing_lines"] > 0
        ):
            buffer.append(
                f"\n{file_name} - {file_index['summary']['missing_lines']} missed lines"
            )
            if file_name.startswith("test_"):
                _fpath = CWD / file_name
            else:
                _fpath = CWD.parent / f"gicp_api/{file_name}"
            with open(_fpath, "r", encoding="utf-8") as sourcefile:
                source_code = sourcefile.readlines()
                for ln in file_index["missing_lines"]:
                    try:
                        buffer.append(
                            f"  {ln}: {source_code[ln - 1].strip()}"
                        )
                    except IndexError:
                        buffer.append(f"{ln}: ERROR RETRIEVING LINE")
    df_report_summary.loc[len(df_report_summary)] = [
        "TOTAL",
        report["totals"]["percent_covered_display"],
        report["totals"]["missing_lines"],
    ]
    with open(
        args.output if args.output is not None else __outfile__,
        "a",
        encoding="utf-8",
    ) as _outfile:
        _outfile.write(
            f"{'-' * 20}\nTEST COVERAGE SUMMARY\n\n"
            + df_report_summary.to_string(index=False)
            + "\n"
        )
        if args.missing and len(buffer) > 0:
            _outfile.write(
                f"\n\n- Missing lines -\n" + "\n".join(buffer) + "\n"
            )


def _format_no_coverage(rdata):
    df_summary = DataFrame(
        columns=["state", "count"],
        data=[(k, v) for k, v in rdata["summary"].items()],
    )
    with open(
        args.output if args.output is not None else __outfile__,
        "a",
        encoding="utf-8",
    ) as _outfile:
        _outfile.write(
            f"{'-' * 20}\nTEST SUMMARY\n\n"
            + df_summary.to_string(index=False)
            + "\n"
        )


def _parse_args(cmd=None):
    parser = argparse.ArgumentParser(
        description="Transform JSON test reports into a more readable format",
    )
    parser.add_argument(
        "-m",
        "--missing",
        action="store_true",
        default=False,
        help="Includes the preview of missed lines for each covered file",
    )
    parser.add_argument(
        "-r",
        "--report",
        help="Path to JSON report. Defaults to host/tests/results/.report.json",
    )
    parser.add_argument(
        "-l",
        "--server-log",
        help="Path to server log. Defaults to host/tests/results/server.log",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Path to output report generated. Defaults to host/tests/results/performance.log",
    )
    return parser.parse_args(cmd)


if __name__ == "__main__":
    args = _parse_args()

    with open(
        args.report if args.report is not None else __report_path__,
        "r",
    ) as reportfile:
        print(
            f"[*] Parsing Pytest report ({reportfile.name.split('tee-integration/')[1]})..."
        )
        report = json_load(reportfile)

    try:
        _format_coverage(report)
    except KeyError:
        _format_no_coverage(report)

    # Include the server logs in the test report
    with open(
        args.output if args.output is not None else __outfile__,
        "a",
        encoding="utf-8",
    ) as outfile:
        outfile.write(f"{'-' * 20}\nSERVER LOGS\n\n```shell\n")
        with open(
            (
                args.server_log
                if args.server_log is not None
                else __server_log__
            ),
            "r",
        ) as f:
            outfile.writelines(f.readlines())
        outfile.write(f"```\n")
        print(
            f"[*] Formatted report generated successfully ({outfile.name.split('tee-integration/')[1]})"
        )
