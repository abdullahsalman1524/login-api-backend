# frozen_string_literal: true

class Users::SessionsController < Devise::SessionsController
  include RackSessionsFix

  respond_to :json

  def create
    # unless request.format.json?
    #   # flash[:alert] = "Invalid request format."
    #   redirect_to new_user_session_path
    #   return
    # end

    # Try to authenticate the user
    self.resource = warden.authenticate!(auth_options)


    if resource
      # Successful authentication
      sign_in(resource_name, resource)
      respond_with(resource, location: after_sign_in_path_for(resource))
    else
      # Authentication failed
      render json: {
        status: {
          code: 401,
          message: 'Invalid email or password.'
        }
      }, status: :unauthorized
    end
  end

  private

  def respond_with(current_user, _opts = {})
    render json: {
      status: {
        code: 200,
        message: 'Logged in successfully.',
        data: { user: UserSerializer.new(current_user).serializable_hash[:data][:attributes] }
      }
    }, status: :ok
  end

  def respond_to_on_destroy
    if request.headers['Authorization'].present?
      jwt_payload = JWT.decode(request.headers['Authorization'].split(' ').last, Rails.application.credentials.devise_jwt_secret_key!).first
      current_user = User.find(jwt_payload['sub'])
    end

    if current_user
      render json: {
        status: 200,
        message: 'Logged out successfully.'
      }, status: :ok
    else
      render json: {
        status: 401,
        message: "Couldn't find an active session."
      }, status: :unauthorized
    end
  end
end
