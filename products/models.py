from django.db import models


class Category(models.Model):
    name = models.CharField(max_length=200)

    def __str__(self):
        return self.name


class Product(models.Model):
    model = models.CharField(max_length=200)
    brand = models.CharField(max_length=200)
    category = models.ForeignKey(Category, on_delete=models.CASCADE)
    quantity = models.IntegerField()
    price = models.FloatField()
    color = models.CharField(max_length=200)
    sell = models.FloatField()
    like = models.BooleanField(default=False)
    evaluation = models.IntegerField()
    size = models.CharField(max_length=200)
    description = models.TextField()

    def __str__(self):
        return self.model


class Photo(models.Model):
    product = models.ForeignKey(Product, related_name='photos', on_delete=models.CASCADE)
    image = models.ImageField(upload_to='product_photos')

    def __str__(self):
        return str(self.product)


class Basket(models.Model):
    products = models.ManyToManyField(Product)
    total_price = models.FloatField()

    def save(self, *args, **kwargs):
        self.total_price = sum([product.price for product in self.products.all()])
        super().save(*args, **kwargs)

    def __str__(self):
        return str(self.total_price)
