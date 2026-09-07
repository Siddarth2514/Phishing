#!/usr/bin/env python3
"""
Setup script for AI-Powered Phishing Detection System
"""

import subprocess
import sys
import os
import json

def install_requirements():
    """Install required packages."""
    print("Installing Python packages...")
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'])
        print("✓ Requirements installed successfully")
        return True
    except subprocess.CalledProcessError:
        print("✗ Failed to install requirements")
        return False

def download_nltk_data():
    """Download required NLTK data."""
    print("Downloading NLTK data...")
    try:
        import nltk
        nltk.download('punkt', quiet=True)
        nltk.download('stopwords', quiet=True)
        nltk.download('vader_lexicon', quiet=True)
        print("✓ NLTK data downloaded successfully")
        return True
    except Exception as e:
        print(f"✗ Failed to download NLTK data: {e}")
        return False

def create_config_file():
    """Create configuration file if it doesn't exist."""
    config_file = 'config.json'
    
    if os.path.exists(config_file):
        print(f"✓ Configuration file {config_file} already exists")
        return True
    
    print(f"Creating default configuration file: {config_file}")
    
    default_config = {
        "detection_threshold": 0.5,
        "alert_recipients": ["security@your-company.com"],
        "notification_methods": ["email"],
        "channels": {
            "email": {
                "server": "imap.gmail.com",
                "port": 993,
                "username": "your_email@gmail.com",
                "password": "your_app_password"
            }
        },
        "alerts": {
            "email": {
                "smtp_server": "smtp.gmail.com",
                "smtp_port": 587,
                "username": "alerts@your-company.com",
                "password": "your_email_password",
                "from_email": "security-alerts@your-company.com"
            }
        }
    }
    
    try:
        with open(config_file, 'w') as f:
            json.dump(default_config, f, indent=2)
        print(f"✓ Created {config_file}")
        print("⚠️  Please update the configuration with your actual credentials")
        return True
    except Exception as e:
        print(f"✗ Failed to create configuration file: {e}")
        return False

def verify_installation():
    """Verify that the installation was successful."""
    print("Verifying installation...")
    
    try:
        # Test imports
        from message_preprocessor import MessagePreprocessor
        from feature_extractor import FeatureExtractor
        from phishing_model import PhishingDetectionModel
        from alert_system import AlertSystem
        from phishing_detection_system import PhishingDetectionSystem
        
        print("✓ All modules imported successfully")
        
        # Test basic functionality
        preprocessor = MessagePreprocessor()
        extractor = FeatureExtractor()
        model = PhishingDetectionModel()
        
        print("✓ Core components initialized successfully")
        return True
        
    except Exception as e:
        print(f"✗ Installation verification failed: {e}")
        return False

def print_next_steps():
    """Print next steps for the user."""
    print("\n" + "="*60)
    print("SETUP COMPLETE!")
    print("="*60)
    
    print("\nNext Steps:")
    print("1. Update config.json with your email/SMS credentials")
    print("2. Train the model: python main.py --train sample_training_data.json")
    print("3. Run demo: python demo.py")
    print("4. Start monitoring: python main.py --monitor")
    
    print("\nDocumentation:")
    print("- Read DOCUMENTATION.md for detailed instructions")
    print("- Check README.md for quick start guide")
    print("- Run tests: python test_system.py")
    
    print("\nConfiguration files:")
    print("- config.json: Main configuration")
    print("- .env: Environment variables (copy from .env.example)")
    
    print("\nFor help:")
    print("- python main.py --help")
    print("- Review sample_training_data.json for data format examples")

def main():
    """Run the complete setup process."""
    print("AI-Powered Phishing Detection System Setup")
    print("="*50)
    
    success = True
    
    # Install requirements
    if not install_requirements():
        success = False
    
    # Download NLTK data
    if not download_nltk_data():
        success = False
    
    # Create config file
    if not create_config_file():
        success = False
    
    # Verify installation
    if not verify_installation():
        success = False
    
    if success:
        print_next_steps()
    else:
        print("\n" + "="*60)
        print("SETUP FAILED!")
        print("="*60)
        print("Please review the errors above and try again.")
        print("You may need to:")
        print("- Install Python 3.7 or later")
        print("- Update pip: python -m pip install --upgrade pip")
        print("- Install packages manually: pip install -r requirements.txt")

if __name__ == '__main__':
    main()