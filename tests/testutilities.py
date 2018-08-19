import difflib
import json
import re
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


if __name__ == "__main__":
    print(next(TestUtilities.get_next_test("../testcases/mac0-tests")))

    str1 = "zuefzepfibuz"
    str2 = "zuefaazepfibuz"

    print(TestUtilities.find_failures(str1, str2))
