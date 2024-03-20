from fastapi import Depends, HTTPException, APIRouter
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from jose import JWTError, jwt
from app.database import collection_ponto, collection_func
from bson.objectid import ObjectId
from datetime import datetime, timedelta
import csv
import smtplib
from io import StringIO
import secrets
import random
import json


router = APIRouter()
class Token(BaseModel):
    access_token: str
    token_type: str

class User(BaseModel):
    user : str
    senha : str = ""
    email : str = ""

SECRET_KEY = "Ta_acabando"
ALGORITHM = "HS256"




def create_access_token(data:dict):
    to_encode = data.copy()
    access_token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return access_token

@router.post('/criar_funcionario')
def criar_user(usuario:User):
    if usuario.user == "" or usuario.email == "":
        raise HTTPException(status_code=403, detail="Para se cadastrar um usuário, precisa informar o user e email")

    senha = secrets.token_urlsafe(random.randint(0,10))
    novo_documento = {
                "NomeFuncionario" : usuario.user,
                "Senha" : senha,
                "Email" : usuario.email
            }
    collection_func.insert_one(novo_documento)
    return {"detail" : f"Funcionario {usuario.user} criado. Senha: {senha}"}

@router.post('/login')
def login(usuario:User):
    filtro = {"NomeFuncionario": usuario.user, "Senha" : usuario.senha}
    # Verificando se o documento existe
    documento = collection_func.find_one(filtro)    
    if documento is None:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")

    user_access_token = create_access_token(data={"_id" : str(documento['_id']), "senha" : documento['Senha']})
    return {"access_token" : user_access_token, "token_type" : "bearer"}

oauth_scheme = OAuth2PasswordBearer(tokenUrl="/login")

def validaToken(token : str):
    try:
        payload = jwt.decode(token,SECRET_KEY, algorithms=[ALGORITHM])
        _id : str = payload.get("_id")
        senha : str = payload.get("senha")
        if _id is None or senha is None:
            raise HTTPException(status_code=401, detail="Token inválido")
        filtro = {"_id": ObjectId(_id), "Senha" : senha}

        # Verificando se o documento existe
        documento = collection_func.find_one(filtro)

        if documento is None:
            raise HTTPException(status_code=404, detail="Usuário não localizado.")
        return documento
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido")

    
def calcular_diferenca_horas(data_inicio, data_fim):
    diferenca = data_fim - data_inicio
    return diferenca.total_seconds() / 3600.0

@router.post('/bater_ponto')
def bater_ponto(token: str = Depends(oauth_scheme)):
    funcionario = validaToken(token)

    data_atual = datetime.now()
    
    data_inicial = datetime(data_atual.year,data_atual.month,data_atual.day,0,0,0,0)
    data_final = datetime(data_atual.year,data_atual.month,data_atual.day+1,0,0,0,0)

    filtro = {
        "IdFuncionario": ObjectId(funcionario['_id']), 
        "DataPonto": {"$gte": data_inicial, "$lt": data_final}
    }
    # Verificando se o documento existe
    documento = collection_ponto.find_one(filtro)

    if documento is None:
        # Se o documento não existir, criar um novo documento
        novo_documento = {
            "IdFuncionario": funcionario['_id'],
            "DataPonto": data_atual,
            "DataInicioExpediente": data_atual
        }
        collection_ponto.insert_one(novo_documento)
        return {"detail" : f"Ponto de início de expediente gravado com sucesso. Data atual: {data_atual}"}

    else:
        # Se o documento existe, verificar os campos
        if "DataSaidaAlmoco" not in documento:
            # Se não existe datasaidaalmoco, preencha
            data_inicio_expediente = documento["DataInicioExpediente"]
            diferenca_saida_almoco = calcular_diferenca_horas(data_inicio_expediente, data_atual)
            collection_ponto.update_one(filtro, {"$set": {"DataSaidaAlmoco": data_atual, "TotalHorasTrabalhadas": diferenca_saida_almoco}})
            return {"detail" : f"Ponto de saída para almoço gravado com sucesso. Data atual: {data_atual}"}

        elif "DataVoltaAlmoco" not in documento:
            # Se não existe datavoltaalmoco, preencha
            collection_ponto.update_one(filtro, {"$set": {"DataVoltaAlmoco": datetime.now()}})
            return { "detail" : f"Ponto de volta de almoço gravado com sucesso. Data atual: {data_atual}"}

        elif "DataFimExpediente" not in documento:
            # Se não existe datafimexpediente, preencha
            data_inicio_expediente = documento["DataInicioExpediente"]            
            data_saida_almoco = documento["DataSaidaAlmoco"]
            data_volta_almoco = documento["DataVoltaAlmoco"]
            diferenca_saida_almoco = calcular_diferenca_horas(data_inicio_expediente, data_saida_almoco)
            diferenca_volta_almoco = calcular_diferenca_horas(data_volta_almoco, data_atual)
            total_horas_trabalhadas = diferenca_saida_almoco + diferenca_volta_almoco

            collection_ponto.update_one(filtro, {"$set": {"DataFimExpediente": data_atual,"TotalHorasTrabalhadas": total_horas_trabalhadas}})
            return {"detail" : f"Ponto de fim de expediente gravado com sucesso. Data atual: {data_atual}"}
        else:
            raise HTTPException(status_code=403, detail="Todos os pontos já foram batidos. Não é possível bater mais ponto.")

@router.get('/obter_ponto_do_dia')
def obterpontododia(token: str = Depends(oauth_scheme)):
    funcionario = validaToken(token)
    data_atual = datetime.now()
    
    data_inicial = datetime(data_atual.year,data_atual.month,data_atual.day,0,0,0,0)
    data_final = datetime(data_atual.year,data_atual.month,data_atual.day+1,0,0,0,0)

    filtro = {
        "IdFuncionario": ObjectId(funcionario['_id']), 
        "DataPonto": {"$gte": data_inicial, "$lt": data_final}
    }
    documento = collection_ponto.find_one(filtro)
    if documento is None:
        raise HTTPException(status_code=404, detail="Não existem pontos para esse funcionário")
    else:
        # Converter os campos ObjectId e datetime para strings
        documento['_id'] = str(documento['_id'])
        documento['IdFuncionario'] = str(documento['IdFuncionario'])
        documento['DataPonto'] = documento['DataPonto'].isoformat()
        documento['DataInicioExpediente'] = documento['DataInicioExpediente'].isoformat()
        documento['DataSaidaAlmoco'] = documento['DataSaidaAlmoco'].isoformat()
        documento['DataVoltaAlmoco'] = documento['DataVoltaAlmoco'].isoformat()
        documento['DataFimExpediente'] = documento['DataFimExpediente'].isoformat()
        
        # Retornar o documento convertido para JSON
        return documento

def gerar_string_csv(registros):
    try:
        # Criar um objeto StringIO para armazenar a string CSV
        csv_buffer = StringIO()
        
        # Configurar o escritor CSV
        writer = csv.DictWriter(csv_buffer, fieldnames=["Id", "IdFuncionario", "DataPonto", "DataInicioExpediente", "DataSaidaAlmoco", "DataVoltaAlmoco", "DataFimExpediente", "TotalHorasTrabalhadas"])
        
        # Escrever o cabeçalho do CSV
        writer.writeheader()
        
        # Escrever os registros no CSV
        for registro in registros:
            writer.writerow({
                "Id": str(registro["_id"]),
                "IdFuncionario": str(registro["IdFuncionario"]),
                "DataPonto": registro["DataPonto"],
                "DataInicioExpediente": registro["DataInicioExpediente"],
                "DataSaidaAlmoco": registro.get("DataSaidaAlmoco", ""),
                "DataVoltaAlmoco": registro.get("DataVoltaAlmoco", ""),
                "DataFimExpediente": registro.get("DataFimExpediente", ""),
                "TotalHorasTrabalhadas": registro.get("TotalHorasTrabalhadas", "")
            })
        
        # Retornar a string CSV
        return csv_buffer.getvalue()
    except Exception as e:
        print("Erro ao gerar string CSV:", e)
        return None

def enviar_email(destinatario, mensagem):
    # Configurações do servidor SMTP
    servidor_smtp = "smtp.gmail.com"
    porta_smtp = 465  # Porta padrão para SMTP
    usuario_smtp = "igor.catrinion@gmail.com"
    senha_smtp = "cavz kkbk yifl mzzm"
    server = smtplib.SMTP_SSL(servidor_smtp, porta_smtp)

    server.login(usuario_smtp, senha_smtp)
    server.sendmail(
        usuario_smtp,
        destinatario,
        mensagem)
    server.quit()

@router.get('/relatorio')
def relatoriomespassado(token: str = Depends(oauth_scheme)):
    funcionario = validaToken(token)

    data_atual = datetime.now()
    
    data_inicial = datetime(data_atual.year,data_atual.month-1,1,0,0,0,0)
    data_final = datetime(data_atual.year,data_atual.month,1,0,0,0,0)

    filtro = {
        "IdFuncionario": ObjectId(funcionario['_id']), 
        "DataPonto": {"$gte": data_inicial, "$lt": data_final}
    }
    # Obtendo todos os registros do mês anterior
    registros_mes_anterior = collection_ponto.find(filtro)
    csv_msg = gerar_string_csv(registros_mes_anterior)
    print(csv_msg)
    print(funcionario['Email'])
    enviar_email(funcionario['Email'], csv_msg)
    return {'detail' : "Registros enviados para o email do funcionario logado."}
    