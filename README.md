### In main-2 branch .csv fils have MySql tabels



create table

Querys for Creating Tables.

create table disease(
    -> diskey int primary key auto_increment,
    -> disname varchar(255),
    -> cases int,
    -> link varchar(255));

create table symptoms(
    -> sympkey int primary key auto_increment,
    -> sympname varchar(255));

create table symptodis(
    -> sympkey int,
    -> diskey int,
    -> question varchar(255),
    -> checks varchar(255),
    -> foreign key (sympkey) references symptoms(sympkey),
    -> foreign key (diskey) references disease(diskey));

Also run the AuthTable.py to create database for Authentication System and make sure to replace the username and password of your mysql with the one given in this file  before running this file.
