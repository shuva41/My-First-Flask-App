from models.store import StoreModel
from models.item import ItemModel
from models.tag import TagModel
from models.items_tags import ItemsTags
from models.user import UserModel

'''
This makes importing the models easier in any part of the code.
Instead of: 
    - from models.store import StoreModel 
    - from models.item import ItemModel
we can write :
    - from models import StoreModel
    - from models import ItemModel
to import the models
'''
