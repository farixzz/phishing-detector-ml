import pandas as pd
df = pd.read_csv('data/master_url_dataset.csv')
print(df['label'].value_counts())

