from flask import Flask, render_template, request, redirect, flash, url_for, make_response
from pymongo import MongoClient
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required, JWTManager
from apscheduler.schedulers.background import BackgroundScheduler; from datetime import timedelta
import secrets; import re; import os; import datetime; from bson.objectid import ObjectId
from flask_cors import CORS; import atexit
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# htttp 환경의 쿠키 설정을 위한 시크릿 키 생성
app.secret_key = os.getenv("FLASK_SECRET_KEY", secrets.token_hex(16))

CORS(app, supports_credentials=True, resources={r"/*": {"origins": "*"}})

# 환경 변수 기반 HTTPS 감지
IS_HTTPS = os.getenv("IS_HTTPS", "false").lower() == "true"

# Flask-JWT 설정
app.config["JWT_SECRET_KEY"] = "WE_ARE_TEAM_5"
app.config["JWT_COOKIE_SECURE"] = IS_HTTPS  # HTTPS 환경이면 True
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_ACCESS_COOKIE_NAME"] = "access_token_cookie"
app.config["JWT_COOKIE_CSRF_PROTECT"] = False  # CSRF 보호 비활성화 
jwt = JWTManager(app)

# MongoDB 연결
client = MongoClient('mongodb://team5:301@43.201.10.192',27017)
db = client.team5

#스케줄러
def create_weekend_matches():
    #날짜를 생성할 때의 현재 날짜 기준으로
    # 토요일과 일요일을 찾아내는 로직
    today = datetime.datetime.today()
    monday = today - datetime.timedelta(days=today.weekday())
    saturday = monday + datetime.timedelta(days=5) #if day=5 => 토요일
    sunday = monday + datetime.timedelta(days=6) # if day=6 => 일요일
    time_slots = ["10:00", "13:00", "19:00"] # 고정적 시간 생성

    # 토요일과 일요일의 날짜를 문자열로 변환
    saturday_date = saturday.strftime("%Y-%m-%d")
    sunday_date = sunday.strftime("%Y-%m-%d")

    # 토요일과 일요일의 일정이 모두 존재하면 로그 출력 후 생략
    # 하나의 요일에 중복 생성 되는 에러 때문에 -> 예외 추가
    if db.schedule.find_one({"date": saturday_date}) and db.schedule.find_one({"date": sunday_date}):
        print("토요일과 일요일의 경기 일정이 모두 존재합니다. 추가 생성하지 않습니다.")
    else:
        for day in [saturday, sunday]:
            match_date = day.strftime("%Y-%m-%d")
            # 이미 해당 날짜에 경기 일정이 있으면 생략
            if db.schedule.find_one({"date": match_date}):
                print(f"{match_date}의 경기 일정이 이미 존재합니다. 생략합니다.")
                continue
            
            #DB 배열 양식 insert
            #schedule 컬렉션에 일자와 시간 반영 후 
            schedule_id = db.schedule.insert_one({ 
                "date": match_date,
                "time_slots": time_slots
            }).inserted_id # schedule_id 에 schedule 컬렉션의 ObjectId 반환

            # 각 시간대별로 reservation 생성
            for time in time_slots:
                db.reservation.insert_one({
                    "match_id": schedule_id,
                    "date": match_date,
                    "time": time,
                    "dead": (day - datetime.timedelta(days=1)).strftime("%Y-%m-%d"),
                    "users": []
                })
        print("경기 생성 완료:", datetime.datetime.now())

# APScheduler 스케줄러 설정 
scheduler = BackgroundScheduler()
#매주 월요일 자정(00:00)에 경기 생성 작업 등록
scheduler.add_job(create_weekend_matches, 'cron', day_of_week='mon', hour=0, minute=0)
scheduler.start()

# 앱 종료 시 스케줄러도 종료되도록 등록
atexit.register(lambda: scheduler.shutdown())

#시간 한글화 함수
def time_change(time) :
        #시간 한글 변환 알고리즘
        time_temp = time.split(':')
        final_time = time_temp[0] + '시' + ' ' +time_temp[1] + '분'
        return final_time
    
## home 홈

@app.route('/')  ## 메인 로그인 페이지
def home():
    return render_template('login.html')

## 회원가입 GET , POST
@app.route('/signup', methods=['GET', 'POST'])  ## 회원가입
def signUp():
    if request.method == 'GET': # 회원가입 html을 단순 렌더
        return render_template("signup.html")

    elif request.method == 'POST': # POST 폼 입력값 저장
        user_id = request.form.get('user_id')
        username = request.form.get('username')
        password = request.form.get('password')
        password_re = request.form.get('password_re')
        phone_num = request.form.get('phone_num')

        #🚨예외처리 입력값 검증
        if not all([user_id, username, password, password_re, phone_num]):
            flash("🚨 모든 값을 입력해야 합니다.", "error")
            return redirect(url_for('signUp'))

        #🚨예외처리 전화번호 형식 검증
        phone_pattern = re.compile(r'^010-\d{4}-\d{4}$')
        if not phone_pattern.match(phone_num):
            flash("🚨 전화번호 형식이 올바르지 않습니다. (예: 010-1234-5678)", "error")
            return redirect(url_for('signUp'))

        #🚨예외처리 아이디 중복 체크
        if db.users.find_one({"user_id": user_id}):
            flash("🚨 이미 존재하는 아이디입니다.", "error")
            return redirect(url_for('signUp'))
        
        #🚨예외처리 휴대폰 번호 중복 체크
        if db.users.find_one({"phone_num": phone_num}):
            flash("🚨 이미 존재하는 휴대폰 번호입니다.", "error")
            return redirect(url_for('signUp'))

        #🚨예외처리 비밀번호 확인값 매칭 
        if password != password_re:
            flash("🚨 비밀번호가 서로 일치하지 않습니다.", "error")
            return redirect(url_for('signUp'))

        # 비밀번호 해싱 후 저장 - 암호화
        hashed_password = generate_password_hash(password)

        # Users 컬렉션 db반영
        db.users.insert_one({
            "user_id": user_id,
            "username": username,
            "password": hashed_password,
            "phone_num": phone_num,
            "reservation": [] # 나의 예약 조회를 위해 예약 컬렉션의 ObjectId 저장 예정
        })

        # ✅HTTP 200 OK 홈으로 리디렉트
        flash("✅ 회원가입이 완료되었습니다! 로그인 해주세요.", "success")
        return redirect(url_for('home'))


## LOGIN POST 요청
@app.route('/login', methods=['POST'])  ## 로그인 API (JWT 활용)
def login():
    user_id = request.form.get("user_id")
    password = request.form.get("password")

    user = db.users.find_one({"user_id": user_id})

    #🚨예외처리 비밀번호 매칭 오류 
    #check hash 매서드를 사용하여 비밀번호 매칭
    if not user or not check_password_hash(user["password"], password):
        flash("🚨 아이디 또는 비밀번호가 올바르지 않습니다.", "error")
        return redirect(url_for('home'))

    #✅HTTP 200 OK JWT 토큰 생성 (만료 시간 1시간 설정)
    access_token = create_access_token(identity=user_id, expires_delta=timedelta(hours=1))


    #✅HTTP 200 OK JWT 토큰을 쿠키에 저장
    response = make_response(redirect(url_for("reservation")))
    response.set_cookie(
        "access_token_cookie", access_token,
        httponly=True,
         secure=IS_HTTPS,  # HTTPS 환경이면 True, HTTP 환경이면 False
        samesite="Lax" if not IS_HTTPS else "None"
    )
    return response


## user의 정보수정 GET, POST
@app.route('/update_user', methods=['GET', 'POST'])
@jwt_required(locations=["cookies"])
def update_user():

    # JWT에 담긴 current_user는 사용자의 아이디(user_id)입니다.
    current_user = get_jwt_identity()

    # current_user(닉네임)를 기준으로 users 콜렉션에서 사용자 조회
    user = db.users.find_one({"user_id": current_user})
    
    if request.method == 'GET':
        return render_template(
            "accountedit.html",
            user_id=user["user_id"],
            username=user["username"],
            phone_num=user["phone_num"],
        )

    if request.method == 'POST':
        password = request.form.get('password')
        password_re = request.form.get('password_re')
        phone_num = request.form.get('phone_num')
        username = request.form.get('username')

        # 🚨예외처리 비밀번호 매칭 오류
        if password != password_re:
            flash("🚨 비밀번호가 서로 일치하지 않습니다.", "error")
            return redirect(url_for('update_user'))

        # 🚨 전화번호 형식 오류
        phone_pattern = re.compile(r'^010-\d{4}-\d{4}$')
        if not phone_pattern.match(phone_num):
            flash("🚨 전화번호 형식이 올바르지 않습니다. (예: 010-1234-5678)", "error")
            return redirect(url_for('update_user'))
        
        # 업데이트할 필드 구성 (전화번호와 사용자명 모두 포함)
        update_data = {
            "phone_num": phone_num,
            "username": username
        }
        # 비밀번호 암호화
        if password:
            hashed_password = generate_password_hash(password)
            update_data["password"] = hashed_password


        #✅HTTP 200 OK  User 컬렉션 업데이트 

        # users 콜렉션 업데이트 (쿼리 조건은 JWT토큰 에서 받은 user_id로 조회)
        db.users.update_one({"user_id": current_user}, {"$set": update_data})
        flash("✅ 유저 정보가 수정되었습니다. 다시 로그인해주세요!", "success")
        return redirect(url_for('home'))

## 로그아웃 API
@app.route('/logout')  # 토큰 담은 쿠키 삭제
def logout():
    response = make_response(redirect(url_for("home"))) # LOGOUT 쿠키 반환 GET
    response.set_cookie("access_token_cookie", "", expires=0) # 쿠키삭제
    flash("✅ 로그아웃 되었습니다.", "success")
    return response

## MYPAGE GET 요청
@app.route('/mypage', methods=['GET']) # mypage GET, POST
@jwt_required(locations=["cookies"]) #토큰 필요한 페이지
def mypage():
    current_user = get_jwt_identity()
    
    #토큰에 저장된 user_id로 유저를 조회 후 해당 유저의 정보를 ssr로 렌더
    user = db.users.find_one({"user_id": current_user})
    return render_template(
        "mypage.html",
         user_id = user["username"]
    )

## 경기 예약 화면 GET
@app.route('/reserve', methods=['GET'])
@jwt_required(locations=["cookies"])
def reservation():
    # """이번 주 경기 조회 및 예약 화면 렌더링 (지난 시간대는 만료 처리)"""
    today = datetime.datetime.today()
    monday = today - datetime.timedelta(days=today.weekday())
    saturday = monday + datetime.timedelta(days=5)
    sunday = monday + datetime.timedelta(days=6)

    # 이번 주 토요일, 일요일 경기만 조회
    # 비교연산자 
    # $gte(greater than or equal) : 크거나 같다,  $lte(less than or equal) : 작거나 같다
    matches = list(db.schedule.find({
        "date": {"$gte": saturday.strftime("%Y-%m-%d"), "$lte": sunday.strftime("%Y-%m-%d")}
    }))

    formatted_matches = []
    for match in matches:
        for time in match["time_slots"]:
            reservation = db.reservation.find_one({"match_id": match["_id"], "time": time})
            reservation_id = str(reservation["_id"]) if reservation else None
            reservation_count = len(reservation["users"]) if reservation else 0

            weekday = "토요일" if match["date"] == saturday.strftime("%Y-%m-%d") else "일요일"

            #예약 시작 시각 계산 (문자열을 datetime 객체로 변환)
            scheduled_datetime = datetime.datetime.strptime(match["date"] + " " + time, "%Y-%m-%d %H:%M")
            is_expired = datetime.datetime.now() > scheduled_datetime #예약 시간이 지났다면 T

            ## 시간반영 알고리즘 테스트 코드
            # scheduled_datetime = datetime.datetime.strptime(match["date"] + " " + time, "%Y-%m-%d %H:%M")
            # test_time = datetime.datetime(2025, 3, 15, 22, 30)
            # is_expired = test_time > scheduled_datetime

            formatted_matches.append({
                "_id": reservation_id,
                "date": match["date"],
                "time": time_change(time),
                "weekday": weekday,
                "reservations": reservation_count,
                "is_expired": is_expired  # Boolean 만료 여부 T/F 
            })

    #현재 만료 기준이나 날짜에 따라 렌더링
    return render_template("reservation.html", matches=formatted_matches)


## 나의 예약 페이지  GET요청
@app.route('/myreserve', methods=['GET'])
@jwt_required(locations=["cookies"])
def my_reserve():
    """유저의 예약 목록 조회 (경기 시작 후 1시간 이후에 만료 처리)"""
    current_user_id = get_jwt_identity()  # JWT에서 user_id (닉네임) 반환
    user_data = db.users.find_one({"user_id": current_user_id})
    if not user_data:
        return render_template("mylist.html", username="알 수 없음", matches=[])

    username = user_data.get("username", "이름 없음")
    if "reservation" not in user_data or not user_data["reservation"]:
        return render_template("mylist.html", username=username, matches=[])

    reservation_ids = user_data["reservation"]
    reservations = list(db.reservation.find({
        "_id": {"$in": [ObjectId(res_id) for res_id in reservation_ids]}
    }))

    matches = []
    for res in reservations:
        match_date = res["date"]  # 예약 날짜 (문자열)
        match_time = res["time"]  # 예약 시간 (문자열)

        # 예약 시작 시각 계산
        scheduled_datetime = datetime.datetime.strptime(match_date + " " + match_time, "%Y-%m-%d %H:%M")
        # 1시간후 만료로 설정 ex) 예약 시간으로 부터 1시간이 지나야 마이페이지 만료
        expiration_datetime = scheduled_datetime + datetime.timedelta(hours=1)
        is_expired = datetime.datetime.now() > expiration_datetime

        ## 시간반영 알고리즘 테스트 코드
        # test_time = datetime.datetime(2025, 3, 15, 10, 30)
        # expiration_datetime = scheduled_datetime + datetime.timedelta(hours=1)
        # is_expired = test_time > expiration_datetime

        # 요일 계산 (예시)
        match_date_obj = datetime.datetime.strptime(match_date, "%Y-%m-%d")
        weekday_map = {5: "토", 6: "일"}
        weekday = weekday_map.get(match_date_obj.weekday(), "")


        matches.append({
            "id": str(res["_id"]),
            "date": match_date,
            "time": time_change(match_time),
            "weekday": weekday,
            "is_expired": is_expired
        })

    return render_template("mylist.html", username=username, matches=matches)

## 나의 예약 조회 GET 요청
@app.route('/myreserve_detail/<match_id>', methods=['GET'])
@jwt_required(locations=["cookies"])
def my_reserve_detail(match_id):
    """나의 예약 상세 정보 조회"""

    try:
        # ObjectId로 변환 (유효성 검증)
        reservation = db.reservation.find_one({"_id": ObjectId(match_id)})
    except Exception:
        return "잘못된 예약 ID입니다.", 400

    if not reservation:
        return "예약 정보를 찾을 수 없습니다.", 404

    # 유저 ID 리스트 추출
    user_list = reservation.get("users", [])

    # users 컬렉션에서 유저 이름 및 핸드폰 번호 조회
    enriched_users = []
    for user in user_list:
        if "user_id" in user:  # 🚨 예외처리 user_id 필드가 있는지 확인
            user_data = db.users.find_one({"_id": ObjectId(user["user_id"])})
            if user_data:
                enriched_users.append({
                    "username": user_data["username"],
                    "phone_num": user_data["phone_num"] 
                })

    return render_template( #반영 정보 기반으로 랜더링
        "myreserv.html",
        reservations=[{
            "id": str(reservation["_id"]),
            "date": reservation["date"],
            "time": time_change(reservation["time"]),
            "count": len(enriched_users),  # 참여 인원 수
            "users": enriched_users  
        }]
    )

## 내 예약 삭제 POST 요청 
@app.route('/mypage/myreserve/<reservation_id>/back', methods=['POST'])
@jwt_required(locations=["cookies"])
def cancel_reservation(reservation_id):
    """유저의 예약 취소 처리"""

    current_user = get_jwt_identity()  #현재 로그인한 유저 ID 가져오기
    user_data = db.users.find_one({"user_id": current_user})

    if not user_data:
        flash("해당 유저 정보를 찾을 수 없습니다.", "error")
        return redirect(url_for("my_reserve"))

    user_object_id = str(user_data["_id"])  #현재 유저의 ObjectId를 **문자열**로 변환하여 비교

    #예약 정보 가져오기 (디버깅)
    reservation = db.reservation.find_one({"_id": ObjectId(reservation_id)})
    print(f"🔹 예약 정보 (수정 전): {reservation}")  # 🚨 디버깅: 현재 예약 정보 확인

    if not reservation:
        flash("해당 예약을 찾을 수 없습니다.", "error")
        return redirect(url_for("my_reserve"))

    #예약에서 현재 사용자 제거 (user_id와 comment 함께 삭제)
    update_result = db.reservation.update_one(
        {"_id": ObjectId(reservation_id)},
        {"$pull": {"users": {"user_id": user_object_id}}}  # ✅ **user_id가 문자열이므로 그대로 비교**
    )

    print(f"🔹 업데이트된 문서 개수: {update_result.modified_count}")  # 🚨 삭제 성공 여부 확인

    #users 컬렉션에서 해당 예약 ID 제거
    db.users.update_one(
        {"user_id": current_user},
        {"$pull": {"reservation": ObjectId(reservation_id)}}
    )

    # 업데이트 후 예약 정보 확인 (디버깅 로그)
    updated_reservation = db.reservation.find_one({"_id": ObjectId(reservation_id)})
    print(f"✅ 업데이트된 예약 정보: {updated_reservation}")  # 🚨 삭제가 정상적으로 반영되었는지 확인

    flash("예약이 취소되었습니다.", "success")
    return redirect(url_for("my_reserve"))  # ✅ 수정된 부분

## 예약상세 GET
@app.route('/reserve/<reservation_id>', methods=['GET'])
@jwt_required(locations=["cookies"])
def reservation_detail(reservation_id):
    """특정 예약 상세 페이지 조회"""
    
    reservation = db.reservation.find_one({"_id": ObjectId(reservation_id)})

    # 유저 ID 리스트 추출
    user_list = reservation.get("users", [])

    #users 컬렉션에서 유저 이름 조회
    enriched_users = []
    for user in user_list:
        user_data = db.users.find_one({"_id": ObjectId(user["user_id"])})
        if user_data:
            enriched_users.append({
                "username": user_data["username"],
                "comment": user["comment"]
            })

    return render_template(
        "comf.html",
        reservation_id=reservation["_id"],
        date=reservation["date"],
        time=time_change(reservation["time"]),
        count=len(user_list),  # 참여 인원 수
        data=enriched_users  # Jinja2에서 사용
    )

## 예약 상세 POST
@app.route('/reserve/<reservation_id>/confirm', methods=['POST'])
@jwt_required(locations=["cookies"])
def reservation_comf(reservation_id):
    """경기 예약 신청을 처리하는 API"""
    current_user = get_jwt_identity()
    comment = request.form.get("comment", "").strip()

    reservation = db.reservation.find_one({"_id": ObjectId(reservation_id)})
    user = db.users.find_one({"user_id": current_user})

    #예약 데이터의 "users" 필드가 존재하는지 확인
    users = reservation.get("users", [])

    #🚨 예외처리 동시 상세화면 진입에 대한 에러 헨들러
    if len(users) >= 6:
        flash("🚨 예약이 마감되었습니다.", "error")
        return redirect(url_for("reservation_detail", reservation_id=reservation_id))

    #🚨 예외처리 중복 경기 예약 
    for u in users:
        if str(u["user_id"]) == str(user["_id"]):
            flash("🚨 이미 참여한 경기입니다.", "error")
            return redirect(url_for("reservation_detail", reservation_id=reservation_id))

    db.reservation.update_one(
        {"_id": ObjectId(reservation_id)},
        {"$push": {"users": {"user_id": str(user["_id"]), "comment": comment}}}
    )

    db.users.update_one(
        {"_id": user["_id"]},
        {"$push": {"reservation": ObjectId(reservation_id)}}
    )


    flash("✅ 예약이 완료되었습니다!", "success")
    return redirect(url_for("reservation_detail", reservation_id=reservation_id))


if __name__ == '__main__':  
   app.run('0.0.0.0', port=5000, debug=True)
