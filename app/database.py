from pymongo import MongoClient
import os

# String de conexão ao banco de dados MongoDB

host = os.environ.get("HOST_DB")
port = os.environ.get("PORT_DB")

uri = f"mongodb://{host}:{port}"

# Nome do banco de dados e coleção
database_name = "hackaton"
collection_ponto = "bat_ponto"
collection_func = "funcionario"

# Criando uma conexão com o servidor MongoDB
client = MongoClient(uri)

# Acessando o banco de dados
database = client[database_name]

# Acessando a coleção
collection_ponto = database[collection_ponto]
collection_func = database[collection_func]