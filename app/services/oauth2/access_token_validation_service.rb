module Oauth2::AccessTokenValidationService
  # Results:
  VALID = :valid
  EXPIRED = :expired
  REVOKED = :revoked
  INSUFFICIENT_SCOPE = :insufficient_scope

  class << self
    def validate(token, scopes: [])
      return EXPIRED if token.expired?
      return REVOKED if token.revoked?
      return INSUFFICIENT_SCOPE if !self.sufficent_scope?(token, scopes)

      VALID
    end

  protected

    def sufficent_scope?(token, scopes)
      return true if scopes.blank?

      required_scopes = Set.new(scopes)
      authorized_scopes = Set.new(token.scopes)

      authorized_scopes >= required_scopes
    end
  end
end
