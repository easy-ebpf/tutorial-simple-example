if status is-interactive
    # Remove default greeting msg
    set -g fish_greeting

    # Utilities
    alias v="nvim"
    alias vim="nvim"
    alias t="tmux"
    alias ta="tmux a"
    alias pa="php artisan"
    alias ls="ls --color=auto"
    alias ll="ls -la"
    alias nthu="sudo openconnect --protocol=nc nthu.twaren.net"
end
