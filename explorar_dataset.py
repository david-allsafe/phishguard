import pandas as pd

# Ler o dataset original
df = pd.read_csv("data/PhiUSIIL_Phishing_URL_Dataset.csv")

# Verificar o tamanho do dataset
print("Total de linhas e colunas:")
print(df.shape)

# Verificar valores em falta
print("\nValores nulos:")
print(df[["URL", "label"]].isnull().sum())

# Verificar URLs repetidos
print("\nURLs duplicados:")
print(df["URL"].duplicated().sum())

# Verificar quantos exemplos existem de cada classe
print("\nDistribuição das classes:")
print(df["label"].value_counts())

# Verificar URLs com classificações contraditórias
conflitos = df.groupby("URL")["label"].nunique()

conflitos = conflitos[conflitos > 1]

print("\nURLs com classificações contraditórias:")
print(len(conflitos))

# Ler o dataset já limpo
limpo = pd.read_csv("data/dataset_limpo.csv")

# Verificar URLs vazios ou com espaços
vazios = limpo["URL"].str.strip().eq("").sum()

# Verificar URLs sem HTTP ou HTTPS
sem_protocolo = ~limpo["URL"].str.startswith(
    ("http://", "https://"),
    na=False
)

# Confirmar classificações
classes_invalidas = ~limpo["label"].isin([0, 1])

print("\nURLs vazios:", vazios)
print("URLs sem HTTP/HTTPS:", sem_protocolo.sum())
print("Classificações inválidas:", classes_invalidas.sum())