"""
Utility functions for XSS detection model
"""
import os
import json
import torch
import numpy as np
from datetime import datetime

class CharacterTokenizer:
    """Character-level tokenizer for XSS detection"""
    
    def __init__(self, vocab=None, max_length=128):
        self.max_length = max_length
        
        if vocab is None:
            # Default vocabulary: special tokens + ASCII printable characters
            self.vocab = {
                '<PAD>': 0,
                '<UNK>': 1,
                '<CLS>': 2,
                '<SEP>': 3
            }
            # Add ASCII printable characters (32-126)
            for i in range(32, 127):
                self.vocab[chr(i)] = len(self.vocab)
        else:
            self.vocab = vocab
            
        self.id_to_token = {v: k for k, v in self.vocab.items()}
    
    def __call__(self, texts, padding='max_length', truncation=True, max_length=None, return_tensors=None):
        """Tokenize a list of texts"""
        if max_length is None:
            max_length = self.max_length
            
        input_ids = []
        attention_mask = []
        
        for text in texts:
            # Convert text to character tokens
            tokens = [self.vocab.get(c, self.vocab['<UNK>']) for c in text]
            
            # Add CLS and SEP tokens
            tokens = [self.vocab['<CLS>']] + tokens + [self.vocab['<SEP>']]
            
            # Truncate if necessary
            if truncation and len(tokens) > max_length:
                tokens = tokens[:max_length-1] + [self.vocab['<SEP>']]
                
            # Create attention mask
            mask = [1] * len(tokens)
            
            # Pad if necessary
            if padding == 'max_length':
                pad_length = max_length - len(tokens)
                tokens = tokens + [self.vocab['<PAD>']] * pad_length
                mask = mask + [0] * pad_length
                
            input_ids.append(tokens)
            attention_mask.append(mask)
            
        # Convert to tensors if requested
        if return_tensors == 'pt':
            input_ids = torch.tensor(input_ids)
            attention_mask = torch.tensor(attention_mask)
            
        return {
            'input_ids': input_ids,
            'attention_mask': attention_mask
        }
    
    def decode(self, token_ids):
        """Decode token IDs back to text"""
        if isinstance(token_ids, torch.Tensor):
            token_ids = token_ids.cpu().numpy()
            
        texts = []
        for ids in token_ids:
            # Convert IDs to characters, skipping special tokens
            text = ''.join([self.id_to_token.get(id, '<UNK>') for id in ids 
                           if id not in [self.vocab['<PAD>'], self.vocab['<CLS>'], self.vocab['<SEP>']]])
            texts.append(text)
            
        return texts
    
    def save(self, path):
        """Save tokenizer vocabulary to file"""
        with open(path, 'w') as f:
            json.dump({
                'vocab': self.vocab,
                'max_length': self.max_length
            }, f)
    
    @classmethod
    def load(cls, path):
        """Load tokenizer from file"""
        with open(path, 'r') as f:
            data = json.load(f)
            
        return cls(vocab=data['vocab'], max_length=data['max_length'])

def save_model(model, tokenizer, config, metrics=None):
    """Save model, tokenizer, config and metrics"""
    # Create timestamp for model versioning
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Get absolute paths for models and experiments directories
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    model_dir = os.path.join(base_dir, 'models')
    os.makedirs(model_dir, exist_ok=True)
    print(f"Saving model to: {model_dir}")
    
    # Save model
    model_path = os.path.join(model_dir, f'best_model_{timestamp}.pt')
    torch.save(model.state_dict(), model_path)
    
    # Save tokenizer
    tokenizer_path = os.path.join(model_dir, f'best_model_{timestamp}_tokenizer.json')
    tokenizer.save(tokenizer_path)
    
    # Save config
    config_path = os.path.join(model_dir, f'best_model_{timestamp}_config.json')
    with open(config_path, 'w') as f:
        json.dump(config, f, indent=2)
    
    # Save metrics if provided
    if metrics is not None:
        # Create experiments directory if it doesn't exist
        exp_dir = os.path.join(base_dir, 'experiments', f'run_{timestamp}')
        os.makedirs(exp_dir, exist_ok=True)
        print(f"Saving experiment results to: {exp_dir}")
        
        # Save metrics
        metrics_path = os.path.join(exp_dir, 'metrics.json')
        with open(metrics_path, 'w') as f:
            json.dump(metrics, f, indent=2)
        
        # Save config used
        config_used_path = os.path.join(exp_dir, 'config_used.json')
        with open(config_used_path, 'w') as f:
            json.dump(config, f, indent=2)
        
        # Create logs directory
        logs_dir = os.path.join(exp_dir, 'logs')
        os.makedirs(logs_dir, exist_ok=True)
    
    return timestamp

def load_model(model_class, timestamp=None):
    """Load model, tokenizer and config"""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    model_dir = os.path.join(base_dir, 'models')
    
    # Get latest model if timestamp not provided
    if timestamp is None:
        model_files = [f for f in os.listdir(model_dir) if f.startswith('best_model_') and f.endswith('.pt')]
        if not model_files:
            raise FileNotFoundError("No model files found")
        
        # Sort by timestamp
        model_files.sort(reverse=True)
        timestamp = model_files[0].split('best_model_')[1].split('.pt')[0]
        print(f"Using latest model with timestamp: {timestamp}")
    
    # Load model
    model_path = os.path.join(model_dir, f'best_model_{timestamp}.pt')
    config_path = os.path.join(model_dir, f'best_model_{timestamp}_config.json')
    tokenizer_path = os.path.join(model_dir, f'best_model_{timestamp}_tokenizer.json')
    
    # Load config
    with open(config_path, 'r') as f:
        config = json.load(f)
    
    # Load tokenizer
    tokenizer = CharacterTokenizer.load(tokenizer_path)
    
    # Create model
    model_params = config['model_params']
    if model_class is not None:
        model = model_class(**config['model_params'])
    elif config['model_type'] == 'lstm':
        model = LSTMClassifier(
            vocab_size=model_params['vocab_size'],
            embedding_dim=model_params['embedding_dim'],
            hidden_size=model_params['hidden_size'],
            num_layers=model_params['num_layers'],
            dropout=model_params['dropout']
        )
    elif config['model_type'] == 'cnn':
        model = CNNClassifier(
            vocab_size=model_params['vocab_size'],
            embedding_dim=model_params['embedding_dim'],
            num_filters=model_params['hidden_size'],
            filter_sizes=model_params['filter_sizes'],
            dropout=model_params['dropout']
        )
    else:
        raise ValueError(f"Unknown model type: {config['model_type']}")
    
    # Load model weights
    model.load_state_dict(torch.load(model_path, map_location=torch.device('cpu')))
    model.eval()
    
    return model, tokenizer, config