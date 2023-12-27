from cryptography.fernet import Fernet
from pathlib import Path
import plotly.graph_objs as go 
import numpy as np

key = Fernet.generate_key()
fernet = Fernet(key)

# read in files as bytes
video = Path('../example/csgo.vmdk') # ahh scary! directory traversal!
with open(video, 'rb') as f:
    video_bytes = f.read()

# generate test sizes
test_sizes = [i for i in range(5, 500, 25)]

# generate test cases
test_cases = list(map(lambda x: video_bytes[0:x*1000000], test_sizes))

# generate sizes of test cases
test_cases_size = list(map(lambda x: len(x)/1000000, test_cases))

# generate encrypted test cases
test_cases_encrypt = list(map(lambda x: fernet.encrypt(x), test_cases))

# generate sizes of encrypted test cases
test_cases_encrypt_size = list(map(lambda x: len(x)/1000000, test_cases_encrypt))

# linear regression
# https://numpy.org/doc/stable/reference/generated/numpy.linalg.lstsq.html
A = np.vstack([test_cases_size, np.ones(len(test_cases_size))]).T 
m, c = np.linalg.lstsq(A, test_cases_encrypt_size, rcond=None)[0]

print(f"linear regression: y = {m}x + {c}")

x_new = np.linspace(test_cases_size[0], test_cases_size[-1], 10)

trace1 = go.Scatter(
    x=test_cases_size, 
    y=test_cases_encrypt_size,
    mode='markers',
    name='Encrypted Data Size',
)

trace2 = go.Scatter(
    x=test_cases_size,
    y=test_cases_size, 
    mode='lines+markers', 
    name='Original Data Size',
)

trace3 = go.Scatter(
    x=x_new, 
    y=x_new*m + c,
    mode='lines', 
    name=f'y = {m}x + {c}',
)

data = [trace1, trace2, trace3]

fig = go.Figure(data=data)
fig.update_layout(
    title='Original vs Encrypted Sizes using Fernet',
    xaxis_title='Size (MB)', 
    yaxis_title='Size (MB)', 
)
fig.write_html('encrypt-plot.html')
