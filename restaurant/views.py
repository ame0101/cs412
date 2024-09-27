from django.shortcuts import render, redirect

# Create your views here.
from datetime import datetime, timedelta
import random

def main(request):
    return render(request, 'main.html')


def order(request):
    daily_specials = ['Special Pizza', 'Special Pasta', 'Special Burger', 'Special Salad']
    context = {
        'daily_special': random.choice(daily_specials)
    }
    return render(request, 'order.html', context)

def confirmation(request):
    if request.method == 'POST':
        order_items = []
        total_price = 0
        
        if request.POST.get('pizza'):
            order_items.append('Pizza')
            total_price += 10  

        
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
            'special_instructions': special_instructions,
            'ready_time': ready_time.strftime("%I:%M %p")
        }
        return render(request, 'confirmation.html', context)
    else:
        return redirect('order')