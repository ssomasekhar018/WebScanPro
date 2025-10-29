"""
Hyperparameter tuning for XSS detection models
"""
import os
import json
import itertools
import numpy as np
from datetime import datetime
from ml.train import train_model, get_default_config

def grid_search(param_grid):
    """Perform grid search over parameter combinations"""
    # Get default config
    base_config = get_default_config()
    
    # Generate all parameter combinations
    param_names = list(param_grid.keys())
    param_values = list(param_grid.values())
    param_combinations = list(itertools.product(*param_values))
    
    print(f"Running grid search with {len(param_combinations)} combinations")
    
    # Store results
    results = []
    
    # Run training for each combination
    for i, combination in enumerate(param_combinations):
        # Update config with current parameter combination
        config = base_config.copy()
        for name, value in zip(param_names, combination):
            config[name] = value
            
        print(f"\nCombination {i+1}/{len(param_combinations)}:")
        for name, value in zip(param_names, combination):
            print(f"  {name}: {value}")
            
        # Train model with current config
        try:
            _, _, metrics, timestamp = train_model(config)
            
            # Store results
            results.append({
                'params': {name: value for name, value in zip(param_names, combination)},
                'val_f1': metrics['val_f1'][-1],
                'val_auc': metrics['val_auc'][-1],
                'test_f1': metrics['test_f1'],
                'test_auc': metrics['test_auc'],
                'timestamp': timestamp
            })
            
            print(f"Validation F1: {metrics['val_f1'][-1]:.4f}, Test F1: {metrics['test_f1']:.4f}")
        except Exception as e:
            print(f"Error training with combination {i+1}: {e}")
    
    # Sort results by validation F1 score
    results.sort(key=lambda x: x['val_f1'], reverse=True)
    
    # Save results
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    results_dir = os.path.join('projects', 'xss_detection', 'experiments')
    os.makedirs(results_dir, exist_ok=True)
    
    results_path = os.path.join(results_dir, f'tuning_results_{timestamp}.json')
    with open(results_path, 'w') as f:
        json.dump(results, f, indent=2)
        
    print(f"\nTuning results saved to {results_path}")
    print("\nTop 3 configurations:")
    for i, result in enumerate(results[:3]):
        print(f"{i+1}. Validation F1: {result['val_f1']:.4f}, Test F1: {result['test_f1']:.4f}")
        for name, value in result['params'].items():
            print(f"  {name}: {value}")
            
    return results

def random_search(param_distributions, n_iter=10):
    """Perform random search over parameter distributions"""
    # Get default config
    base_config = get_default_config()
    
    print(f"Running random search with {n_iter} iterations")
    
    # Store results
    results = []
    
    # Run training for each random combination
    for i in range(n_iter):
        # Sample random parameters
        config = base_config.copy()
        sampled_params = {}
        
        for name, distribution in param_distributions.items():
            if isinstance(distribution, list):
                # Categorical parameter
                value = np.random.choice(distribution)
            elif isinstance(distribution, tuple) and len(distribution) == 2:
                # Uniform continuous parameter
                low, high = distribution
                value = np.random.uniform(low, high)
            elif isinstance(distribution, tuple) and len(distribution) == 3:
                # Log-uniform continuous parameter
                low, high, log = distribution
                if log:
                    value = np.exp(np.random.uniform(np.log(low), np.log(high)))
                else:
                    value = np.random.uniform(low, high)
                    
            config[name] = value
            sampled_params[name] = value
            
        print(f"\nIteration {i+1}/{n_iter}:")
        for name, value in sampled_params.items():
            print(f"  {name}: {value}")
            
        # Train model with current config
        try:
            _, _, metrics, timestamp = train_model(config)
            
            # Store results
            results.append({
                'params': sampled_params,
                'val_f1': metrics['val_f1'][-1],
                'val_auc': metrics['val_auc'][-1],
                'test_f1': metrics['test_f1'],
                'test_auc': metrics['test_auc'],
                'timestamp': timestamp
            })
            
            print(f"Validation F1: {metrics['val_f1'][-1]:.4f}, Test F1: {metrics['test_f1']:.4f}")
        except Exception as e:
            print(f"Error training with iteration {i+1}: {e}")
    
    # Sort results by validation F1 score
    results.sort(key=lambda x: x['val_f1'], reverse=True)
    
    # Save results
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    results_dir = os.path.join('projects', 'xss_detection', 'experiments')
    os.makedirs(results_dir, exist_ok=True)
    
    results_path = os.path.join(results_dir, f'tuning_results_{timestamp}.json')
    with open(results_path, 'w') as f:
        json.dump(results, f, indent=2)
        
    print(f"\nTuning results saved to {results_path}")
    print("\nTop 3 configurations:")
    for i, result in enumerate(results[:3]):
        print(f"{i+1}. Validation F1: {result['val_f1']:.4f}, Test F1: {result['test_f1']:.4f}")
        for name, value in result['params'].items():
            print(f"  {name}: {value}")
            
    return results

if __name__ == "__main__":
    # Define parameter grid for grid search
    small_param_grid = {
        'model_type': ['lstm', 'cnn'],
        'learning_rate': [1e-4, 5e-4, 1e-3],
        'embedding_dim': [64, 128],
        'hidden_size': [64, 128],
        'dropout': [0.3, 0.5]
    }
    
    # Define parameter distributions for random search
    param_distributions = {
        'model_type': ['lstm', 'cnn'],
        'learning_rate': (1e-4, 1e-2, True),  # log-uniform between 1e-4 and 1e-2
        'embedding_dim': [64, 128, 256],
        'hidden_size': [64, 128, 256],
        'dropout': (0.1, 0.5, False),  # uniform between 0.1 and 0.5
        'batch_size': [32, 64, 128]
    }
    
    # Choose tuning method
    tuning_method = input("Select tuning method (grid/random): ").strip().lower()
    
    if tuning_method == 'grid':
        print("Running grid search...")
        results = grid_search(small_param_grid)
    elif tuning_method == 'random':
        n_iter = int(input("Number of random iterations: "))
        print(f"Running random search with {n_iter} iterations...")
        results = random_search(param_distributions, n_iter=n_iter)
    else:
        print("Invalid tuning method. Please choose 'grid' or 'random'.")