import json

# Notebook 1: EDA and Threat Detection
notebook1 = {
    "cells": [
        {
            "cell_type": "markdown",
            "metadata": {},
            "source": [
                "# Branch 1: Exploratory Data Analysis & Basic Threat Detection\n",
                "\n",
                "This notebook focuses on:\n",
                "- Loading and exploring log data\n",
                "- Basic statistical analysis\n",
                "- Initial threat pattern detection (SQL injection, XSS, Path Traversal)\n",
                "- Status code distribution and error analysis\n",
                "- Traffic pattern visualization\n",
                "\n",
                "**Analysis Branch:** Foundational EDA & Pattern Recognition"
            ]
        },
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [
                "# Import required libraries\n",
                "import sys\n",
                "import pandas as pd\n",
                "import numpy as np\n",
                "import matplotlib.pyplot as plt\n",
                "import seaborn as sns\n",
                "import warnings\n",
                "from datetime import datetime\n",
                "\n",
                "# Add parent directory to path\n",
                "sys.path.append('..')\n",
                "\n",
                "# Import custom modules\n",
                "from log_threat_detection.dataset import LogDataset\n",
                "from log_threat_detection.models import ThreatDetector\n",
                "from log_threat_detection.config import *\n",
                "\n",
                "# Configuration\n",
                "warnings.filterwarnings('ignore')\n",
                "plt.style.use('seaborn-v0_8-whitegrid')\n",
                "sns.set_palette('husl')\n",
                "\n",
                "print('✓ Libraries imported successfully')"
            ]
        }
    ],
    "metadata": {
        "kernelspec": {
            "display_name": "Python 3",
            "language": "python",
            "name": "python3"
        },
        "language_info": {
            "name": "python",
            "version": "3.8.0"
        }
    },
    "nbformat": 4,
    "nbformat_minor": 4
}

# Notebook 2: Anomaly Detection
notebook2 = {
    "cells": [
        {
            "cell_type": "markdown",
            "metadata": {},
            "source": [
                "# Branch 2: Anomaly Detection Analysis\n",
                "\n",
                "This notebook focuses on:\n",
                "- Statistical anomaly detection in traffic patterns\n",
                "- Time-series analysis of request volumes\n",
                "- IP behavior profiling and anomaly detection\n",
                "- Error spike detection and correlation\n",
                "- Machine learning-based outlier detection\n",
                "\n",
                "**Analysis Branch:** Statistical & ML-based Anomaly Detection"
            ]
        },
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [
                "# Import required libraries\n",
                "import sys\n",
                "import pandas as pd\n",
                "import numpy as np\n",
                "import matplotlib.pyplot as plt\n",
                "import seaborn as sns\n",
                "import warnings\n",
                "from datetime import datetime\n",
                "from scipy import stats\n",
                "from sklearn.preprocessing import StandardScaler\n",
                "from sklearn.ensemble import IsolationForest\n",
                "\n",
                "# Add parent directory to path\n",
                "sys.path.append('..')\n",
                "\n",
                "# Import custom modules\n",
                "from log_threat_detection.dataset import LogDataset\n",
                "from log_threat_detection.models import AnomalyDetector\n",
                "from log_threat_detection.config import *\n",
                "\n",
                "# Configuration\n",
                "warnings.filterwarnings('ignore')\n",
                "plt.style.use('seaborn-v0_8-whitegrid')\n",
                "sns.set_palette('Set2')\n",
                "\n",
                "print('✓ Libraries imported successfully')"
            ]
        }
    ],
    "metadata": {
        "kernelspec": {
            "display_name": "Python 3",
            "language": "python",
            "name": "python3"
        },
        "language_info": {
            "name": "python",
            "version": "3.8.0"
        }
    },
    "nbformat": 4,
    "nbformat_minor": 4
}

# Notebook 3: Risk Assessment
notebook3 = {
    "cells": [
        {
            "cell_type": "markdown",
            "metadata": {},
            "source": [
                "# Branch 3: Security Threat Classification & Risk Assessment\n",
                "\n",
                "This notebook focuses on:\n",
                "- Comprehensive threat categorization and severity scoring\n",
                "- Multi-dimensional risk assessment framework\n",
                "- IP reputation and threat intelligence integration\n",
                "- Attack pattern classification and trend analysis\n",
                "- Actionable security recommendations\n",
                "\n",
                "**Analysis Branch:** Risk Assessment & Classification"
            ]
        },
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [
                "# Import required libraries\n",
                "import sys\n",
                "import pandas as pd\n",
                "import numpy as np\n",
                "import matplotlib.pyplot as plt\n",
                "import seaborn as sns\n",
                "import warnings\n",
                "from datetime import datetime\n",
                "\n",
                "# Add parent directory to path\n",
                "sys.path.append('..')\n",
                "\n",
                "# Import custom modules\n",
                "from log_threat_detection.dataset import LogDataset\n",
                "from log_threat_detection.models import ThreatDetector\n",
                "from log_threat_detection.config import *\n",
                "\n",
                "# Configuration\n",
                "warnings.filterwarnings('ignore')\n",
                "plt.style.use('seaborn-v0_8-whitegrid')\n",
                "sns.set_palette('muted')\n",
                "\n",
                "print('✓ Libraries imported successfully')"
            ]
        }
    ],
    "metadata": {
        "kernelspec": {
            "display_name": "Python 3",
            "language": "python",
            "name": "python3"
        },
        "language_info": {
            "name": "python",
            "version": "3.8.0"
        }
    },
    "nbformat": 4,
    "nbformat_minor": 4
}

# Write notebooks
with open('1.01-eda-and-threat-detection.ipynb', 'w', encoding='utf-8') as f:
    json.dump(notebook1, f, indent=1, ensure_ascii=False)
    
with open('2.01-anomaly-detection-analysis.ipynb', 'w', encoding='utf-8') as f:
    json.dump(notebook2, f, indent=1, ensure_ascii=False)
    
with open('3.01-security-threat-classification.ipynb', 'w', encoding='utf-8') as f:
    json.dump(notebook3, f, indent=1, ensure_ascii=False)

print("✓ Created all 3 notebooks successfully!")
print("  - 1.01-eda-and-threat-detection.ipynb")
print("  - 2.01-anomaly-detection-analysis.ipynb")
print("  - 3.01-security-threat-classification.ipynb")
