from .python.parser import PythonParser
from .python.process_package import process_python_package

all_parsers = [PythonParser]
package_processors = {
    "python-package": process_python_package
}
