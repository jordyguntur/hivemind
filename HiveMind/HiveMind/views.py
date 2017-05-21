from django.shortcuts import render

# This just returns our home.html file
def home(request):
    return render(request, 'index.html')
def about(request):
    return render(request, 'about.html')
