import datetime
from flask_mongoengine import MongoEngine
from mongoengine import *
from main import app
db = MongoEngine(app)
class UserDetails(Document):
    first_name = StringField(null=False)
    last_name = StringField(null=False)
    email = EmailField(null=False,unique=True)
    password= StringField()
    created_date=DateTimeField(default=datetime.datetime.now())
    status=BooleanField(default=True)

    def to_json(self):
        return {
            "_id": str(self.pk),
            "First Name": self.first_name,
            "Last Name": self.last_name,
            "Email": self.email,
        }
class TemplateDetails(Document):
    user_id = ReferenceField(UserDetails)
    template_name = StringField(null=False)
    subject = StringField(null=False)
    body = EmailField(null=False, unique=True)
    created_date = DateTimeField(default=datetime.datetime.now())
    status = BooleanField(default=True)

    def to_json(self):
        return {
            "Template Id": str(self.pk),
            "User Id": str(self.user_id),
            "Template Name": self.template_name,
            "Subject": self.subject,
            "Body": self.body,
        }