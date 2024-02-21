from rest_framework.routers import DefaultRouter
from django.urls import path, include
from .views import *

router = DefaultRouter()
router.register(r'categories', CategoryViewSet)
router.register(r'products', ProductViewSet)
router.register(r'photos', PhotoViewSet)
router.register(r'baskets', BasketViewSet)

urlpatterns = [
    path('', include(router.urls)),
]



