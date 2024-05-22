# -*- coding: utf-8 -*-
"""
TRACE_THE_WUMPUS
Copyright (C) 2014-2024 Leitwert GmbH

This software is distributed under the terms of the MIT license.
It can be found in the LICENSE file or at https://opensource.org/licenses/MIT.

Author Johann SCHLAMP <schlamp@leitwert.net>
Author Leonhard RABEL <rabel@leitwert.net>
"""

# Local imports
from wumpus.const import Input
from wumpus.const import Output
from wumpus.iputil import input_ip
from wumpus.iputil import output_ip
from wumpus.session import Session


class Game:
    """ Game instance.
    """
    def __init__(self, debug=False):
        """ Initialize game.
        """
        # Prepare internals
        self.sessions = dict()
        self.debug = debug
        self.error = False

    def handle_input(self, client, target):
        """ Handle game input represented by <target> for player identified by <client>.
        """
        # Reset error
        self.error = False

        def handle():
            """ Generate output message(s) for given input command.
            """
            # Clear expired sessions
            for player in list(self.sessions):
                if self.sessions[player].expired() is True:
                    del self.sessions[player]

            # Access or initialize client session
            session = self.sessions.get(client, None)
            if session is None:
                session = Session(debug=self.debug)
                self.sessions[client] = session

            # Renew timeout of client session
            self.sessions[client].update()

            # Parse target details
            cmd, action = input_ip(target)

            # Output debug message
            cmd_str = cmd.__name__.lower() if cmd is not None else '?'
            action_str = str(action)
            session.log_debug(f'CMD   [client={client}, target={target}, cmd={cmd_str}, action={action_str}]')

            # Handle game commands
            if cmd == Input.Game:

                # Display IPv4 fallback
                if action == Input.Game.IPV4:
                    return session.output_ipv4()

                # Display help
                if action == Input.Game.HELP:
                    return session.output_help()
                session.last_help = -1

                # Display map
                if action == Input.Game.MAP:
                    return session.output_map()

                # Welcome new player
                if action == Input.Game.START:
                    session.clear()
                    return session.output_title()

                # Start new game
                if action == Input.Game.PLAY:
                    session.new()
                    return session.output_state(initial=True)

                # Disallow any actions (expired session)
                if session.live is False:
                    return session.output_expired()

                # Replay last game
                if action == Input.Game.REPLAY:
                    session.reset()
                    return session.output_state(initial=True)

                # Invalid command
                self.error = True
                return session.output_invalid()

            # Handle invalid command
            if cmd not in {Input.Move, Input.Shoot}:
                self.error = True
                return session.output_invalid()

            # Disallow any commands (expired session)
            if session.live is False:
                return session.output_expired()

            # Disallow any commands (already won)
            if session.won is True:
                return session.output_win()

            # Disallow any commands (already lost)
            if session.lost is True:
                return session.output_loss()

            # Handle move command
            if cmd == Input.Move:
                return session.move(action) + session.output_state()

            # Handle shoot command
            if cmd == Input.Shoot:
                return session.shoot(action) + session.output_state()

            # Handle invalid command
            self.error = True
            return session.output_invalid()

        # Handle input commands and prepare output messages
        output = handle()
        output_ips = [output_ip(oid) for oid in (output if isinstance(output, (list, tuple)) is True else [output])]

        # Add target to output mesage
        if self.error is False:
            if target not in set(output_ips):
                output_ips.append(target)
        else:
            output_ips.append(output_ip(Output.GAME_EMPTY))

        # Return output messages
        return output_ips
