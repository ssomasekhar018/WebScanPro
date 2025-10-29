"""
Model definitions for XSS detection
"""
import torch
import torch.nn as nn
import torch.nn.functional as F

class LSTMClassifier(nn.Module):
    """LSTM-based classifier for XSS detection"""
    
    def __init__(self, vocab_size, embedding_dim=128, hidden_size=128, 
                 num_layers=2, dropout=0.3, num_numerical_features=6):
        super(LSTMClassifier, self).__init__()
        
        self.embedding = nn.Embedding(vocab_size, embedding_dim, padding_idx=0)
        self.lstm = nn.LSTM(
            embedding_dim, 
            hidden_size, 
            num_layers=num_layers, 
            bidirectional=True, 
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0
        )
        
        # Global attention pooling
        self.attention = nn.Linear(hidden_size * 2, 1)
        
        # Numerical features processing
        self.numerical_fc = nn.Linear(num_numerical_features, hidden_size)
        
        # Final classification layers
        self.fc1 = nn.Linear(hidden_size * 2 + hidden_size, hidden_size)
        self.dropout = nn.Dropout(dropout)
        self.fc2 = nn.Linear(hidden_size, 1)
        
    def forward(self, input_ids, attention_mask, numerical_features):
        # Embedding layer
        embedded = self.embedding(input_ids)
        
        # Apply mask to embeddings
        mask_expanded = attention_mask.unsqueeze(-1).expand(embedded.size())
        embedded = embedded * mask_expanded
        
        # LSTM layer
        lstm_output, _ = self.lstm(embedded)
        
        # Apply attention mask to LSTM output
        mask_expanded = attention_mask.unsqueeze(-1).expand(lstm_output.size())
        lstm_output = lstm_output * mask_expanded
        
        # Attention pooling
        attention_weights = self.attention(lstm_output)
        attention_weights = attention_weights.masked_fill(attention_mask.unsqueeze(-1) == 0, -1e10)
        attention_weights = F.softmax(attention_weights, dim=1)
        context_vector = torch.sum(lstm_output * attention_weights, dim=1)
        
        # Process numerical features
        numerical_vector = F.relu(self.numerical_fc(numerical_features))
        
        # Concatenate context vector and numerical features
        combined = torch.cat([context_vector, numerical_vector], dim=1)
        
        # Final classification
        output = F.relu(self.fc1(combined))
        output = self.dropout(output)
        output = self.fc2(output)
        
        return torch.sigmoid(output).squeeze()

class CNNClassifier(nn.Module):
    """CNN-based classifier for XSS detection"""
    
    def __init__(self, vocab_size, embedding_dim=128, num_filters=128, 
                 filter_sizes=[3, 5, 7], dropout=0.3, num_numerical_features=6):
        super(CNNClassifier, self).__init__()
        
        self.embedding = nn.Embedding(vocab_size, embedding_dim, padding_idx=0)
        
        # Multiple convolutional layers with different kernel sizes
        self.convs = nn.ModuleList([
            nn.Conv1d(embedding_dim, num_filters, kernel_size)
            for kernel_size in filter_sizes
        ])
        
        # Numerical features processing
        self.numerical_fc = nn.Linear(num_numerical_features, num_filters)
        
        # Final classification layers
        self.fc1 = nn.Linear(num_filters * len(filter_sizes) + num_filters, num_filters)
        self.dropout = nn.Dropout(dropout)
        self.fc2 = nn.Linear(num_filters, 1)
        
    def forward(self, input_ids, attention_mask, numerical_features):
        # Embedding layer
        embedded = self.embedding(input_ids)
        
        # Apply mask to embeddings
        mask_expanded = attention_mask.unsqueeze(-1).expand(embedded.size())
        embedded = embedded * mask_expanded
        
        # Transpose for conv1d which expects [batch, embedding, sequence]
        embedded = embedded.transpose(1, 2)
        
        # Apply convolutions and max-pooling
        conv_outputs = []
        for conv in self.convs:
            # Convolution
            conv_output = F.relu(conv(embedded))
            
            # Global max pooling
            pooled = F.max_pool1d(conv_output, conv_output.size(2)).squeeze(2)
            conv_outputs.append(pooled)
        
        # Concatenate all conv outputs
        conv_cat = torch.cat(conv_outputs, dim=1)
        
        # Process numerical features
        numerical_vector = F.relu(self.numerical_fc(numerical_features))
        
        # Concatenate conv outputs and numerical features
        combined = torch.cat([conv_cat, numerical_vector], dim=1)
        
        # Final classification
        output = F.relu(self.fc1(combined))
        output = self.dropout(output)
        output = self.fc2(output)
        
        return torch.sigmoid(output).squeeze()

# Simple baseline model using TF-IDF features
class SimpleBaselineModel(nn.Module):
    """Simple baseline model for XSS detection"""
    
    def __init__(self, input_dim, hidden_dim=64, dropout=0.3):
        super(SimpleBaselineModel, self).__init__()
        
        self.fc1 = nn.Linear(input_dim, hidden_dim)
        self.dropout = nn.Dropout(dropout)
        self.fc2 = nn.Linear(hidden_dim, 1)
        
    def forward(self, x):
        x = F.relu(self.fc1(x))
        x = self.dropout(x)
        x = self.fc2(x)
        return torch.sigmoid(x).squeeze()