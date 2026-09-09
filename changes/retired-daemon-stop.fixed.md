Allow a daemon that retired its generation markers during clean shutdown to
finish exiting before reporting an identity error. No unverified process is
signalled; runtime cleanup still requires the singleton lock.
