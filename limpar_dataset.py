import pandas as pd

# Ler o dataset original
df = pd.read_csv("data/PhiUSIIL_Phishing_URL_Dataset.csv")

# Selecionar apenas as colunas necessárias
df = df[["URL", "label"]].copy()

# Remover valores nulos
df = df.dropna(subset=["URL", "label"])

# Remover URLs duplicados
df = df.drop_duplicates(subset=["URL"])

# Guardar o dataset limpo
df.to_csv("data/dataset_limpo.csv", index=False)

print("Dataset limpo criado!")
print("Total de registos:", len(df))