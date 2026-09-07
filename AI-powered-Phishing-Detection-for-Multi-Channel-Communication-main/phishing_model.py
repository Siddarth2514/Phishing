import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
import logging
from typing import Dict, List, Any, Tuple
import os

class PhishingDetectionModel:
    """Machine learning model for phishing detection."""
    
    def __init__(self, model_path: str = None):
        self.logger = logging.getLogger(__name__)
        self.model = None
        self.scaler = StandardScaler()
        self.feature_names = None
        self.is_trained = False
        self.model_path = model_path or 'phishing_model.pkl'
        
        # Define the ensemble model
        self._create_model()
        
    def _create_model(self):
        """Create ensemble model with multiple classifiers."""
        # Individual classifiers
        rf_classifier = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            class_weight='balanced'
        )
        
        lr_classifier = LogisticRegression(
            random_state=42,
            class_weight='balanced',
            max_iter=1000
        )
        
        svm_classifier = SVC(
            kernel='rbf',
            probability=True,
            random_state=42,
            class_weight='balanced'
        )
        
        # Create voting classifier
        self.model = VotingClassifier(
            estimators=[
                ('rf', rf_classifier),
                ('lr', lr_classifier),
                ('svm', svm_classifier)
            ],
            voting='soft'
        )
        
    def prepare_features(self, features_list: List[Dict[str, float]]) -> np.ndarray:
        """Prepare features for training or prediction."""
        if not features_list:
            return np.array([])
            
        # Convert to DataFrame
        df = pd.DataFrame(features_list)
        
        # Fill missing values
        df = df.fillna(0)
        
        # Store feature names if not already stored
        if self.feature_names is None:
            self.feature_names = df.columns.tolist()
        
        # Ensure all expected features are present
        for feature in self.feature_names:
            if feature not in df.columns:
                df[feature] = 0
                
        # Reorder columns to match training data
        df = df[self.feature_names]
        
        return df.values
    
    def train(self, features_list: List[Dict[str, float]], labels: List[int], 
              test_size: float = 0.2, perform_grid_search: bool = False) -> Dict[str, Any]:
        """Train the phishing detection model."""
        self.logger.info("Starting model training...")
        
        # Prepare features
        X = self.prepare_features(features_list)
        y = np.array(labels)
        
        if len(X) == 0:
            raise ValueError("No features provided for training")
            
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Perform grid search if requested
        if perform_grid_search:
            self._perform_grid_search(X_train_scaled, y_train)
        
        # Train the model
        self.model.fit(X_train_scaled, y_train)
        self.is_trained = True
        
        # Evaluate the model
        train_score = self.model.score(X_train_scaled, y_train)
        test_score = self.model.score(X_test_scaled, y_test)
        
        # Cross-validation
        cv_scores = cross_val_score(self.model, X_train_scaled, y_train, cv=5)
        
        # Predictions for detailed metrics
        y_pred = self.model.predict(X_test_scaled)
        y_pred_proba = self.model.predict_proba(X_test_scaled)[:, 1]
        
        # Calculate metrics
        roc_auc = roc_auc_score(y_test, y_pred_proba)
        
        results = {
            'train_accuracy': train_score,
            'test_accuracy': test_score,
            'cv_mean_accuracy': cv_scores.mean(),
            'cv_std_accuracy': cv_scores.std(),
            'roc_auc': roc_auc,
            'classification_report': classification_report(y_test, y_pred),
            'confusion_matrix': confusion_matrix(y_test, y_pred).tolist()
        }
        
        self.logger.info(f"Model training completed. Test accuracy: {test_score:.4f}")
        
        return results
    
    def _perform_grid_search(self, X_train: np.ndarray, y_train: np.ndarray):
        """Perform grid search for hyperparameter tuning."""
        self.logger.info("Performing grid search for hyperparameter tuning...")
        
        param_grid = {
            'rf__n_estimators': [50, 100, 200],
            'rf__max_depth': [5, 10, 15],
            'lr__C': [0.1, 1, 10],
            'svm__C': [0.1, 1, 10],
            'svm__gamma': ['scale', 'auto']
        }
        
        grid_search = GridSearchCV(
            self.model, param_grid, cv=3, scoring='roc_auc', n_jobs=-1
        )
        
        grid_search.fit(X_train, y_train)
        self.model = grid_search.best_estimator_
        
        self.logger.info(f"Best parameters: {grid_search.best_params_}")
        
    def predict(self, features: Dict[str, float]) -> Tuple[int, float]:
        """Predict if a message is phishing."""
        if not self.is_trained:
            raise ValueError("Model must be trained before making predictions")
            
        # Prepare features
        X = self.prepare_features([features])
        X_scaled = self.scaler.transform(X)
        
        # Make prediction
        prediction = self.model.predict(X_scaled)[0]
        probability = self.model.predict_proba(X_scaled)[0, 1]
        
        return int(prediction), float(probability)
    
    def predict_batch(self, features_list: List[Dict[str, float]]) -> List[Tuple[int, float]]:
        """Predict for multiple messages."""
        if not self.is_trained:
            raise ValueError("Model must be trained before making predictions")
            
        # Prepare features
        X = self.prepare_features(features_list)
        X_scaled = self.scaler.transform(X)
        
        # Make predictions
        predictions = self.model.predict(X_scaled)
        probabilities = self.model.predict_proba(X_scaled)[:, 1]
        
        return list(zip(predictions.astype(int), probabilities.astype(float)))
    
    def save_model(self, path: str = None):
        """Save the trained model to disk."""
        if not self.is_trained:
            raise ValueError("Model must be trained before saving")
            
        save_path = path or self.model_path
        
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'feature_names': self.feature_names,
            'is_trained': self.is_trained
        }
        
        joblib.dump(model_data, save_path)
        self.logger.info(f"Model saved to {save_path}")
        
    def load_model(self, path: str = None):
        """Load a trained model from disk."""
        load_path = path or self.model_path
        
        if not os.path.exists(load_path):
            raise FileNotFoundError(f"Model file not found: {load_path}")
            
        model_data = joblib.load(load_path)
        
        self.model = model_data['model']
        self.scaler = model_data['scaler']
        self.feature_names = model_data['feature_names']
        self.is_trained = model_data['is_trained']
        
        self.logger.info(f"Model loaded from {load_path}")
        
    def get_feature_importance(self) -> Dict[str, float]:
        """Get feature importance from the Random Forest classifier."""
        if not self.is_trained:
            raise ValueError("Model must be trained to get feature importance")
            
        # Get the Random Forest classifier from the voting classifier
        rf_classifier = self.model.named_estimators_['rf']
        
        if self.feature_names is None:
            raise ValueError("Feature names not available")
            
        importances = rf_classifier.feature_importances_
        feature_importance = dict(zip(self.feature_names, importances))
        
        # Sort by importance
        return dict(sorted(feature_importance.items(), key=lambda x: x[1], reverse=True))