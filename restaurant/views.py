from django.shortcuts import render, redirect
from datetime import datetime, timedelta
import random

def main(request):
    return render(request, 'main.html')

def main_view(request):
    return render(request, 'main.html') 

def order_view(request):
    specials = [
        {'name': 'Mofongo', 'price': 10.99},
        {'name': 'Chicharrón de Pollo', 'price': 12.99},
        {'name': 'Sancocho', 'price': 14.99}
    ]
    daily_special = random.choice(specials)
    context = {
        'daily_special': daily_special
    }
    return render(request, 'order.html', context)

def confirmation(request):
    if request.method == 'POST':
        order_items = []
        total_price = 0

        if request.POST.get('daily_special'):
            order_items.append(request.POST.get('daily_special_name'))
            total_price += float(request.POST.get('daily_special_price'))

        name = request.POST.get('name')
        phone = request.POST.get('phone')
        email = request.POST.get('email')
        special_instructions = request.POST.get('special_instructions')

        ready_time = datetime.now() + timedelta(minutes=random.randint(30, 60))

        context = {
            'order_items': order_items,
            'total_price': total_price,
            'name': name,
            'phone': phone,
            'email': email,
            'special_instructi