from pathlib import Path
from abc import ABC, abstractmethod
import shutil
import argparse

class Base_suspicious_file_scanner(ABC):
    def __init__(self, root: Path):
        self.root = Path(root)
        self.DANGEROUS_WORDS = ["crack", "keygen", "payload", "exploit", "trojan", "backdoor"]
        self.EXTENSION_EXECUTABLE = [".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".msi"]
        self.DOCUMENT_EXTENSIONS = [".pdf", ".doc", "docx", ".xls", "xlsx", ",jpg", ".jpeg", ".png", ".txt"]
        self.SMALL_LIMIT_EXE_BYTE = 10 * 1024
        
        self.suspicious_extensions = []
        self.suspicious_filenames = []
        self.suspicious_exe_size = []

        self.total_path_size: int = 0

        @abstractmethod
        def find_suspicious_file(self):
            pass

        @abstractmethod
        def analyze_suffix(self):
            pass

        @abstractmethod
        def display_normal(self):
            pass

        @abstractmethod
        def display_verbose(self):
            pass

        @abstractmethod
        def analyze_word(self):
            pass

        @abstractmethod
        def analyze_file(self):
            pass
    
class Suspicious_file_scanner(Base_suspicious_file_scanner):

    def analyze_suffix(self) -> list:
        for file in self.root.rglob("*"):
            if file.suffix in self.EXTENSION_EXECUTABLE:
                self.suspicious_extensions.append(file)

        return self.suspicious_extensions

    def analyze_word(self):
        for file in self.root.rglob("*"):
            for word in range(len(self.DANGEROUS_WORDS)):
                if self.DANGEROUS_WORDS[word] in file.name:
                    self.suspicious_filenames.append(file)

    def accumulate_exe(self) -> int:
        for file in self.root.rglob("*"):
            if file.is_file() and file.suffix == ".exe":
                self.total_path_size += file.stat().st_size

    def find_suspicious_file(self):
        self.analyze_suffix()
        self.analyze_word()

    def analyze_file(self):
        self.accumulate_exe()

    


    def display(self, status: bool):
        def display_normal(list_extensions: list, list_filenames: list):
            print("===== Suspicious file extensions =====")
            for i, x in enumerate(list_extensions, start=1):
                print(f"{i}. {x.name}")
            print()

            print("===== Suspicious filenames =====")
            for i, x in enumerate(list_filenames, start=1):
                print(f"{i}. {x.name}")

        def display_verbose(list_extensions: list, list_filenames: list):
            print("===== Suspicious file extensions =====")
            for i, x in enumerate(list_extensions, start=1):
                print(f"{i}. {x.resolve()}")
            print()

            print("===== Suspicious filenames =====")
            for i, x in enumerate(list_filenames, start=1):
                print(f"{i}. {x.resolve()}")
            print()

            print(f"path size: {self.total_path_size / 1000} MB")
            print("===== Suspicious exe size =====")

            
            
        sus_extension = self.suspicious_extensions
        sus_filename = self.suspicious_filenames
        if status:
            display_verbose(sus_extension, sus_filename)
        else:
            display_normal(sus_extension, sus_filename)


def main():
    parser = argparse.ArgumentParser()
    parser.usage = "Run like this -> file.py [path] or file.py ([-x] / [--x]) [path]" 
    parser.add_argument("path", help="path address")
    parser.add_argument("-v", "--verbose", help="provides a verbose description", action="store_true")
    
    args: argparse.Namespace = parser.parse_args()
    root: Path = args.path

    program = Suspicious_file_scanner(root)
    program.find_suspicious_file()  
    program.analyze_file()
    program.display(args.verbose)
    


if __name__ == "__main__":
    main()