import json
from os import listdir, path


class TestUtilities:

    @staticmethod
    def get_next_test(directory: str):
        for file in listdir(directory):
            file_path = path.join(directory, file)
            yield TestUtilities._extract(file_path)

    @staticmethod
    def _extract(file: str):
        with open(file, 'r') as f:
            current_test_case = json.loads(f.read())
        return current_test_case
