from django.shortcuts import render, redirect
from datetime import datetime, timedelta
import random

def main(request):
    return render(request, 'restaurant/main.html')

def main_view(request):
    return render(request, 'restaurant/main.html') 


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
    return render(request, 'restaurant/order.html', context)

def confirmation(request):
    if request.method == 'POST':
        order_items = []
        total_price = 0

        # Handle daily special fields
        if request.POST.get('daily_special_name') and request.POST.get('daily_special_price'):
            order_items.append(request.POST.get('daily_special_name'))
            try:
                total_price += float(request.POST.get('daily_special_price'))
            except ValueError:
                # Handle the case where the price is not a valid number
                total_price += 0

        # Get other form fields
        name = request.POST.get('name')
        phone = request.POST.get('phone')
        email = request.POST.get('email')
        special_instructions = request.POST.get('special_instructions')

        # Calculate the ready time
        ready_time = datetime.now() + timedelta(minutes=random.randint(30, 60))

        # Create the context for the confirmation page
        context = {
            'order_items': order_items,
            'total_price': total_price,
            'name': name,
            'phone': phone,
            'email': email,
            'special_instructions': special_instructions,
            'ready_time': ready_time.strftime("%I:%M %p")
        }

        return render(request, 'restaurant/confirmation.html', context)
    else:
        return redirect('order')
