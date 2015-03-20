from setuptools import setup, find_packages


def get_requirements():
    with open('requirements.txt') as f:
        return f.read().splitlines()


def get_long_description():
    with open('README.md') as f:
        rv = f.read()
    return rv


setup(
    name='Flask-ACL',
    version='0.1.0',
    description='Access control lists for Flask.',
    long_description=get_long_description(),
    url='http://github.com/mikeboers/Flask-ACL',
    author='Mike Boers',
    author_email='flask-acl@mikeboers.com',
    license='BSD-3',
    packages=find_packages(),
    zip_safe=False,
    include_package_data=True,
    install_requires=get_requirements(),
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2',
    ],
)
