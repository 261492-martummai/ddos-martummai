import csv
from datetime import datetime
import os
import threading
from typing import Protocol

import requests


class OutputWriter(Protocol):
    def write(self, data: dict) -> None:
        raise NotImplementedError


class CSVWriter(OutputWriter):
    def __init__(self, output_file) -> None:
        self.file = open(output_file, "w")
        self.line = 0
        self.writer = csv.writer(self.file)

    def write(self, data: dict) -> None:
        if self.line == 0:
            self.writer.writerow(data.keys())

        self.writer.writerow(data.values())
        self.file.flush()
        self.line += 1

    def __del__(self):
        self.file.close()


class RotatingCSVWriter:
    def __init__(self, output_dir, max_rows=1000) -> None:
        self.output_dir = output_dir
        self.max_rows = max_rows
        self.line_count = 0
        self.file_index = 0
        self.current_file = None
        self.writer = None

        self.lock = threading.Lock()

        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

        self._open_new_file()

    def _open_new_file(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{timestamp}_flow_data_{self.file_index}.csv"
        self.current_filepath = os.path.join(self.output_dir, filename)

        self.current_file = open(self.current_filepath, "a", newline="")
        self.writer = csv.writer(self.current_file)
        self.line_count = 0
        self.file_index += 1
        self.header_written = False

    def _rotate(self):
        if self.current_file:
            self.current_file.flush()
            self.current_file.close()

        self._open_new_file()

    def write(self, data: dict) -> None:
        with self.lock:
            if not self.header_written:
                self.writer.writerow(list(data.keys()))
                self.header_written = True

            self.writer.writerow(list(data.values()))
            self.line_count += 1

            if self.line_count >= self.max_rows:
                self._rotate()

    def __del__(self):
        if hasattr(self, "lock"):
            with self.lock:
                if self.current_file and not self.current_file.closed:
                    self.current_file.close()


class HttpWriter(OutputWriter):
    def __init__(self, output_url) -> None:
        self.url = output_url
        self.session = requests.Session()

    def write(self, data):
        try:
            resp = self.session.post(self.url, json=data, timeout=5)
            resp.raise_for_status()  # raise if not 2xx
        except Exception:
            self.logger.exception("HTTPWriter failed posting flow")

    def __del__(self):
        self.session.close()


def output_writer_factory(output_mode, output, rotate_rows=1000000) -> OutputWriter:
    match output_mode:
        case "url":
            return HttpWriter(output)
        case "csv":
            return RotatingCSVWriter(output, max_rows=rotate_rows)
        case "pcap":
            return CSVWriter(output)
        case _:
            raise RuntimeError("no output_mode provided")
