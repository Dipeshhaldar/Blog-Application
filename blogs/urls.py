from django.urls import path
from . import views


urlpatterns = [
    path('<int:category_id>/', views.posts_by_category, name='posts_by_category'),
    # path('like/<int:pk>', views.like_blog, name="like_blog"),
]