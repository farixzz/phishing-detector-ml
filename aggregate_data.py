import pandas as pd
import os
from url_normalizer import normalize_url 

def aggregate_and_clean_data():
    kaggle_path = os.path.join('data', 'phishing_site_urls.csv')
    phishtank_path = os.path.join('data', 'verified_online.csv')
    output_path = os.path.join('data', 'master_url_dataset.csv')

    print("Loading datasets...")
    kaggle_df = pd.read_csv(kaggle_path)
    phishtank_df = pd.read_csv(phishtank_path)
    
    # Prepare Kaggle data
    kaggle_df.rename(columns={'URL': 'url', 'Label': 'label'}, inplace=True)
    kaggle_df['label'] = kaggle_df['label'].map({'bad': 1, 'good': 0})

    # Prepare PhishTank data
    phishtank_df = phishtank_df[['url']]
    phishtank_df['label'] = 1
    
    # Combine
    master_df = pd.concat([kaggle_df[['url', 'label']], phishtank_df], ignore_index=True)
    master_df.dropna(subset=['url'], inplace=True)
    master_df.drop_duplicates(subset=['url'], keep='first', inplace=True)

    # Normalize every URL in the dataset before saving.
    print("Normalizing all URLs in the dataset...")
    master_df['url'] = master_df['url'].apply(normalize_url)
    # -----------------------
    
    # Clean duplicates again after normalization
    master_df.drop_duplicates(subset=['url'], keep='first', inplace=True)
    master_df = master_df.sample(frac=1, random_state=42).reset_index(drop=True)

    master_df.to_csv(output_path, index=False)
    print(f"✅✅✅ Final, NORMALIZED master dataset created with {len(master_df)} URLs. ✅✅✅")

if __name__ == '__main__':
    aggregate_and_clean_data()
