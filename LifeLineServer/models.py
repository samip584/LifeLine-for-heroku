from LifeLineServer import driver_db, traffic_db, driver_ma, traffic_ma

# Driver Class/Model
class Driver(driver_db.Model):
    did = driver_db.Column(driver_db.Integer, primary_key=True)
    name = driver_db.Column(driver_db.String(200))
    driver_id = driver_db.Column(driver_db.String(200), unique=True)
    email = driver_db.Column(driver_db.String(200), unique=True)
    contact = driver_db.Column(driver_db.String(10), unique=True)
    password = driver_db.Column(driver_db.String(200))
    pic = driver_db.Column(driver_db.LargeBinary)
    role = 'driver'

    def __init__(self, name, driver_id, email, contact, password):
        self.name = name
        self.driver_id = driver_id
        self.email = email
        self.contact = contact
        self.password = password

    def put_pic(self, pic):
        self.pic = pic

    def update_data(self, name, driver_id, email, contact):
        self.name = name
        self.driver_id = driver_id
        self.email = email
        self.contact = contact

    def update_password(self, password):
        self.password = password


# Driver Schema
class DriverSchema(driver_ma.Schema):
    class Meta:
        fields = ('id', 'name', 'driver_id', 'email',
                  'contact', 'password', 'pic', 'role')


# Traffic Class/Model
class Traffic(traffic_db.Model):
    tid = traffic_db.Column(traffic_db.Integer, primary_key=True)
    name = traffic_db.Column(traffic_db.String(100))
    email = traffic_db.Column(traffic_db.String(200), unique=True)
    contact = driver_db.Column(driver_db.String(10), unique=True)
    password = traffic_db.Column(traffic_db.String(200))
    pic = traffic_db.Column(traffic_db.LargeBinary)
    role='traffic'

    def __init__(self, name, email, contact, password):
        self.name = name
        self.email = email
        self.contact = contact
        self.password = password

    def put_pic(self, pic):
        self.pic = pic

    def update_data(self, name, email, contact):
        self.name = name
        self.email = email
        self.contact = contact
    
    def update_password(self, password):
        self.password = password


# Traffic Schema
class TrafficSchema(traffic_ma.Schema):
    class Meta:
        fields = ('id', 'name', 'email', 'contact', 'password', 'pic', 'role')