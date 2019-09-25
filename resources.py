import os
from flask_restful import Resource, reqparse
from models import UserModel
from flask import json, request
from run import mysql
from run import app
import datetime
import requests
import urllib3

from flask import jsonify, make_response
from werkzeug import secure_filename
import random
import string
from flask_jwt_extended import (create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt)


pool_manager = urllib3.PoolManager()
register = reqparse.RequestParser()
auth = reqparse.RequestParser()
join = reqparse.RequestParser()
task = reqparse.RequestParser()
edittask = reqparse.RequestParser()
file = reqparse.RequestParser()
task_data = reqparse.RequestParser()
#parser.add_argument('username', help = 'This field cannot be blank',location='form', required = True)
register.add_argument('username', help = 'This field cannot be blank', required = True)
register.add_argument('password', help = 'This field cannot be blank', required = True)
register.add_argument('email', help= 'This field cannot be blank', required = True)
register.add_argument('kantor', help= 'This field cannot be blank', required = True)
register.add_argument('no_hp', help= 'This field cannot be blank', required = True)
register.add_argument('alamat', help= 'This field cannot be blank', required = True)


auth.add_argument('username', help = 'This field cannot be blank or use json body Parameter', location='json', required = True)
auth.add_argument('password', help = 'This field cannot be blank or use json body Parameter', location='json', required = True)

#Parser For Join Task
join.add_argument('id_task', help='this field cannot be blank', location='json', required= True)
join.add_argument('id_user', help='this field cannot be blank', location='json', required= True)
join.add_argument('roles', help='this field cannot be blank', location='json', required= True)

#Parser For Create Respone
task.add_argument('id_respone', help='this field cannot be blank', location='json', required= True)
task.add_argument('id_user', help='this field cannot be blank', location='json', required= True)
task.add_argument('alamat', help='this field cannot be blank', location='json', required= True)
task.add_argument('sumber_respone', help='this field cannot be blank', location='json', required= True)
task.add_argument('tgl', help='this field cannot be blank', location='json', required= True)
task.add_argument('catatan', help='this field cannot be blank', location='json', required= True)
task.add_argument('status', help='this field cannot be blank', location='json', required= True)
task.add_argument('minat_lokasi', help='this field cannot be blank', location='json', required= True)
task.add_argument('jadwal', help='this field cannot be blank', location='json', required= True)

#parser For Edit Respone
edittask.add_argument('nama_konsument', help='this field cannot be blank', location='json', required= True)
edittask.add_argument('alamat', help='this field cannot be blank', location='json', required= True)
edittask.add_argument('sumber_respone', help='this field cannot be blank', location='json', required= True)
edittask.add_argument('tgl', help='this field cannot be blank', location='json', required= True)
edittask.add_argument('catatan', help='this field cannot be blank', location='json', required= True)
edittask.add_argument('status', help='this field cannot be blank', location='json', required= True)
edittask.add_argument('minat_lokasi', help='this field cannot be blank', location='json', required= True)
edittask.add_argument('jadwal', help='this field cannot be blank', location='json', required= True)

file.add_argument('file[]', location=['headers', 'values'])

#data
task_data.add_argument('geolocation', help = 'This field cannot be blank',location='form', required = True)
task_data.add_argument('keterangan', help = 'This field cannot be blank',location='form', required = True)


def randomString():
    for x in range(100):
        return random.randint(1,1100000)
class UserRegistration(Resource):
    def post(self):
        data = register.parse_args()

        if UserModel.find_by_username(data['username']):
            return {
            'success':'false',
            'message': 'User {} already exists'. format(data['username'])}
        
        if UserModel.find_by_email(data['email']):
            return {
            'success':'false',
            'message': 'Email {} already exists'. format(data['email'])}

        new_user = UserModel(
            username = data['username'],
            password = UserModel.generate_hash(data['password']),
            email    = data['email'],
            kantor   = data['kantor'],
            no_hp    = data['no_hp'],
            alamat   = data['alamat']
        )

        try:
            new_user.save_to_db()
            access_token = create_access_token(identity = data['username'])
            refresh_token = create_refresh_token(identity = data['username'])
            return {
                'success':'true',
                'message': 'User {} was created'.format(data['username']),
                'access_token': access_token,
                'refresh_token': refresh_token
                }
        except:
            return {'success': 'false'}, 500


class UserLogin(Resource):
    def post(self):
        data = auth.parse_args()
        current_user = UserModel.find_by_username(data['username'])
        if not current_user:
            return {
            'success':'false',
            'message': 'User {} doesn\'t exist'.format(data['username'])}
        
        if UserModel.verify_hash(data['password'], current_user.password):
            access_token = create_access_token(identity = data['username'])
            refresh_token = create_refresh_token(identity = data['username'])
            return {
                'message': 'Logged in as {}'.format(current_user.username),
                'access_token': access_token,
                'refresh_token': refresh_token
                }
        else:
            return {'message': 'Wrong credentials'}


class GetUser(Resource):
    @jwt_required    
    def get(self, id_user=None):
        if not id_user:
            return 404
        # Do stuff
        return UserModel.find_by_user(id_user)

class UserLogoutAccess(Resource):
    @jwt_required
    def post(self):
        jti = get_raw_jwt()['jti']
        try:
            revoked_token = RevokedTokenModel(jti = jti)
            revoked_token.add()
            return {'message': 'Access token has been revoked'}
        except:
            return {'message': 'Something went wrong'}, 500


class UserLogoutRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        jti = get_raw_jwt()['jti']
        try:
            revoked_token = RevokedTokenModel(jti = jti)
            revoked_token.add()
            return {'message': 'Refresh token has been revoked'}
        except:
            return {'message': 'Something went wrong'}, 500


class TokenRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        current_user = get_jwt_identity()
        access_token = create_access_token(identity = current_user)
        return {'access_token': access_token}

class AllUsers(Resource):
    def get(self):
        return UserModel.return_all()
    
    def delete(self):
        return UserModel.delete_all()





#==========This For Tables Task===================


class JoinTask(Resource):
    def post(self):
        data = join.parse_args()
        conn = mysql.connect()
        cursor = conn.cursor()

        result=cursor.execute("SELECT * from Join_task where id_task = %s AND id_user = %s", (data['id_task'], data['id_user']))
        
        if (result):
                return {'success':'false',
                        'message': 'Task already join'}
        else:  

                cursor.execute(
                """INSERT INTO Join_task (
                id_task,
                id_user,
                roles
                ) 
                VALUES (%s,%s,%s)""",(data['id_task'],data['id_user'],data['roles']))
                conn.commit()
                conn.close()
                return {'success':'true'}        

class ShowTask(Resource):
    @jwt_required
    def get(self, id_user=None):
        conn = mysql.connect()
        cursor = conn.cursor()
        result = cursor.execute("SELECT * from Respone WHERE id_user= %s ",int(id_user))
        data = cursor.fetchall()
        results = []
        if(result):
            for item in data:
                dataResponse = {
                'id_respone'     : item[0],
                'alamat'     : item[2],
                'nama_konsumen': item[3],
                'sumber_respone'   : item[4],
                'catatan'  : item[6],
                ##'tgl': datetime.datetime(item[4])
           }
                results.append(dataResponse)
            return ({'success':'true',
                    'data':results})
        else:
            return json.dumps({'data':'null'})

class DeleteRespone(Resource):
    def get(self, id_respone=None):
        conn = mysql.connect()
        cursor = conn.cursor()
        result = cursor.execute("DELETE FROM Respone WHERE id_respone = %s",int(id_respone))
        conn.commit()
        conn.close()
        if(result):
            return {'success':'true'}
        else:
            return {'success':'false'}


class CreateTask(Resource):
    def post(self):
        data = task.parse_args()
        conn = mysql.connect()
        cursor = conn.cursor()
        id_respone=randomString()
        id_user=data['id_user']
        result = cursor.execute(
        """INSERT INTO Respone ( 
                id_user,  
                alamat,
                nama_konsument,
                sumber_respone,
                tgl,
                catatan,
                status,
                minat_lokasi,
                jadwal
            ) 
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",(id_user,data['alamat'],data['nama_konsument'],data['sumber_respone'],data['tgl'],data['catatan'],data['status'],data['minat_lokasi'],data['jadwal']))
        conn.commit()
        conn.close()
        ##level='boss'
        if(result): 
            return {"success":"success"}
            ##return JoinTask_Create(id_task,id_user,level, data['description'], data['name_location'])
        else:
            return {"success":"false"}

def JoinTask_Create(id_task, id_user, level, descriptions, name_location): 
        conn = mysql.connect()
        cursor = conn.cursor()
        cursor.execute(
        """INSERT INTO Join_task (
                id_task,
                id_user,
                roles
            ) 
            VALUES (%s,%s,%s)""",(id_task,id_user,level))
        conn.commit()
        conn.close()
        return {'success':'true',
                'data':{
                'id_task':id_task,
                'description':descriptions,
                'name_location':name_location
                }
                }

class UpdateTask(Resource):
        def post(self, id_respone=None):
            data = edittask.parse_args()            
            conn = mysql.connect()
            cursor = conn.cursor()
            result = cursor.execute("UPDATE Respone SET alamat = %s, nama_konsument = %s, sumber_respone = %s, tgl = %s, catatan = %s, status = %s, minat_lokasi = %s, jadwal = %s WHERE id_respone = %s",
                            (data['alamat'],data['nama_konsument'],data['sumber_respone'],data['tgl'],data['catatan'],data['status'],data['minat_lokasi'],data['jadwal'],int(id_respone)))
            conn.commit()
            conn.close()
            if(result):
                return {'success':'true'}
            else:
                return {'success':'false'}

class Apicuaca(Resource):
        def get(self):
            result = requests.get("http://dataservice.accuweather.com/locations/v1/cities/geoposition/search?apikey=z1nydrXnaR8Ai0uSwKLN192GjLzNsggI&q=-7.769025, 110.390743")
            #URL=""
            #key={'apikey':'z1nydrXnaR8Ai0uSwKLN192GjLzNsggI&q','q':'-7.769025, 110.390743'}
            ##r = requests.get(url = URL)
            #print(example_request.status) # Status code.
            #print(example_request.headers["Content-Type"]) # Content type.
            #ini = example_request.data
            #print r.json
            return result.json()


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in app.config['ALLOWED_EXTENSIONS']


def randomFile(stringLength=25):
    """Generate a random string of fixed length """
    letters= string.ascii_lowercase
    return ''.join(random.sample(letters,stringLength))


def insert(uniqe_name,uniqe_name_data):
    conn = mysql.connect()
    cursor = conn.cursor()
    cursor.execute(
    """INSERT INTO Gambar (related_id,name_gambar) 
    VALUES (%s,%s)""",(uniqe_name_data,uniqe_name))
    conn.commit()
    conn.close()

def insert_data(id_task,geolocation,keterangan,uniqe_name_data):
    conn = mysql.connect()
    cursor = conn.cursor()
    cursor.execute(
    """INSERT INTO Data (id_task,geolocation,keterangan,related_gambar) 
    VALUES (%s,%s,%s,%s)""",(id_task,geolocation,keterangan,uniqe_name_data))
    conn.commit()
    conn.close()

