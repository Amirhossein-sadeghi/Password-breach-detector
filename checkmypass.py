import requests
import hashlib
import sys


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    response = requests.get(url)
    # print(response)
    if response.status_code != 200:
        raise RuntimeError(f'Error fetching: {response.status_code}, check the API and try again.')
    return response


def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    # check password if it exists in API response
    sha1pasword = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    # print(sha1pasword)
    first5_char, tail = sha1pasword[:5], sha1pasword[5:]
    response = request_api_data(first5_char)
    # print(first5_char,tail)
    return get_password_leaks_count(response, tail)


def main(args):
    for password in args:
        count= pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times... you should probably change your password')
        else:
            print(f'{password} was not found. Carry on!')
    return 'done!'


if __name__=='__main__':
    sys.exit(main(sys.argv[1:]))
