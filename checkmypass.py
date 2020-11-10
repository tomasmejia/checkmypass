import requests
import hashlib
import sys


def request_data(query):
    url = 'https://api.pwnedpasswords.com/range/' + query
    res = requests.get(url)

    if res.status_code != 200:
        raise RuntimeError(
            f'Error fetching: {res.status_code}, check the API and try again.')
    return res


def get_password_leaks(hashes, hash_to_check):
    hashes = (line.split(":") for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def password_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first_five_chars, tail = sha1password[:5], sha1password[5:]
    response = request_data(first_five_chars)
    return get_password_leaks(response, tail)


def main(args):
    for password in args:
        count = password_check(password)
        if count:
            print(
                f'{password} was found {count} times. You probably should change your password.')
        else:
            print(f'Your password, {password}, seems safe, for now!')
    return 'Done.'


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
